import type { AuthClient, Principal } from './index';

/*
 * The Fastify adapter.
 *
 * ⛔ WHAT THIS IS NOT: a second implementation. Every property that matters — the
 * three-way classification, the 60-second positive cache, the 5-second negative cache,
 * the single-flight de-duplication, the resolver contract and the refusal-vs-indeterminate
 * distinction — lives behind `client.verify()`. This file contains no cache, no map, no
 * timer and no HTTP call. If it ever grows one, it has stopped being an adapter.
 *
 * ⛔ THE SHORTCUT DELIBERATELY NOT TAKEN. `@fastify/express` runs Express middleware
 * unchanged under Fastify, and would have made this file unnecessary. It is rejected
 * because of WHERE it writes: that plugin hands middleware the raw Node request, so
 * `req.principal = …` lands on the raw object, while a Fastify handler reads
 * `request.principal` on Fastify's own Request. The two are not the same object, so the
 * principal would be set somewhere nothing reads — a gate that appears to run, reports
 * success, and decorates nothing. That is precisely the failure class this package exists
 * to remove, so importing it to save a file would have been the wrong trade.
 *
 * ── What actually differs between the two frameworks, and it is three things, not one ──
 *
 *   1. MOUNTING. Express takes middleware positionally: `router.get(path, mw, handler)`.
 *      Fastify takes it as a route option: `app.get(path, { preHandler: [mw] }, handler)`.
 *   2. CONTINUATION. Express continues by CALLING `next()`. A Fastify preHandler continues
 *      by RETURNING without having replied. There is no next() to forget, which removes one
 *      failure mode and adds another: a preHandler that returns after replying is a
 *      double-send, so this adapter always returns immediately after it replies.
 *   3. REFUSAL. `res.status(n).json(b)` against `reply.status(n).send(b)`.
 *
 * Nothing about the request or reply SHAPES forces more than that: both expose
 * `headers.authorization` as a string, and both are decorated by assignment.
 *
 * ── No dependency on fastify ──
 * The types below are structural on purpose. This package does not depend on fastify, does
 * not list it as a peer, and a service that never imports this file never pays for it.
 */

/** The minimum of a Fastify request this adapter touches. */
export interface FastifyLikeRequest {
  headers: Record<string, string | string[] | undefined>;
  [key: string]: unknown;
}

/** The minimum of a Fastify reply this adapter touches. */
export interface FastifyLikeReply {
  status(code: number): { send(payload: unknown): unknown };
}

export type FastifyLikeHandler = (
  request: FastifyLikeRequest,
  reply: FastifyLikeReply,
) => Promise<void>;

export interface FastifyAuth {
  /** Mount as `{ preHandler: [auth.requireAuth] }`. */
  requireAuth: FastifyLikeHandler;
  /** Mount AFTER requireAuth, on organisation-scoped routes only. */
  requireOrgMembership: FastifyLikeHandler;
}

function bearerFrom(request: FastifyLikeRequest): string | null {
  const raw = request.headers.authorization;
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (typeof header !== 'string' || !header.startsWith('Bearer ') || header.length <= 7) {
    return null;
  }
  return header.slice(7);
}

export function createFastifyAuth(client: AuthClient): FastifyAuth {
  if (!client || typeof client.verify !== 'function') {
    throw new Error(
      'createFastifyAuth: pass the client returned by createAuthClient. The adapter has no ' +
        'verification of its own by design — it is a wrapper, not an implementation.',
    );
  }

  const requireAuth: FastifyLikeHandler = async (request, reply) => {
    const token = bearerFrom(request);
    if (token === null) {
      await reply.status(401).send({ error: 'missing_bearer_token' });
      return;
    }

    const result = await client.verify(token);

    if (result.kind === 'refused') {
      await reply.status(401).send({ error: 'invalid_token' });
      return;
    }
    if (result.kind === 'indeterminate') {
      // 503, not 401 — the credential was never judged. Same rule as the Express side.
      await reply.status(503).send({ error: 'auth_service_unavailable', detail: result.reason });
      return;
    }

    // Substitute, never validate: drop every x-user-* the caller sent, then set the
    // canonical names from the verified principal.
    for (const name of Object.keys(request.headers)) {
      if (name.toLowerCase().startsWith('x-user-')) delete request.headers[name];
    }
    request.headers['x-user-id'] = result.principal.userId;
    request.headers['x-user-identifier'] = result.principal.userId;
    request.principal = result.principal;
    // Returning without replying is how a Fastify preHandler continues. There is no next().
  };

  const requireOrgMembership: FastifyLikeHandler = async (request, reply) => {
    const principal = request.principal as Principal | undefined;
    if (!principal) {
      await reply.status(500).send({ error: 'auth_middleware_misordered' });
      return;
    }

    const raw = request.headers['x-org-id'];
    const organisationId = Array.isArray(raw) ? raw[0] : raw;
    if (typeof organisationId !== 'string' || organisationId.trim() === '') {
      await reply.status(403).send({ error: 'organisation_required' });
      return;
    }

    let member: boolean;
    try {
      member = await client.isMemberOfOrganisation(principal, organisationId);
    } catch {
      await reply.status(503).send({ error: 'membership_check_unavailable' });
      return;
    }
    if (!member) {
      await reply.status(403).send({ error: 'not_a_member_of_organisation' });
      return;
    }
    // Organisation headers are untouched: validated, never substituted.
  };

  return { requireAuth, requireOrgMembership };
}
