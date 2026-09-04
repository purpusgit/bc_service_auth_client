import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { introspect, type Introspection } from './introspect';
import { TtlCache } from './cache';

export type { Introspection };
export { TtlCache } from './cache';
export { introspect };

/**
 * Positive cache lifetime. THIS IS A SECURITY PARAMETER, NOT A TUNING KNOB, and it is
 * deliberately not configurable: it is the revocation reach. See the README section
 * "Revocation, and the 60 seconds" for why this number is the whole story.
 */
const POSITIVE_TTL_MS = 60_000;

/**
 * Negative cache lifetime. Short on purpose: a refusal that is cached too long makes a
 * restored session wait, and one that is not cached at all turns a credential-stuffing
 * flood into unthrottled load on /token/validate -- which costs the auth service a
 * database READ and a WRITE per call, and is the single point of failure for every
 * signed-in request in the estate. Also not configurable.
 */
const NEGATIVE_TTL_MS = 5_000;

const MAX_ENTRIES = 5_000;

export interface Principal {
  /** The verified subject. The access token carries `{ userId }` and nothing else. */
  userId: string;
  /** Whatever `resolveLocalIdentity` returned, when one was supplied. */
  local?: unknown;
}

export type MembershipPredicate = (
  principal: Principal,
  organisationId: string,
) => boolean | Promise<boolean>;

/**
 * What a resolver is given in addition to the principal.
 *
 * DELIBERATELY ONE FIELD. The obvious design is to hand the resolver the request, and it is
 * the wrong one: the request carries the `x-user-*` headers this package has just
 * overwritten, the organisation headers it validates but does not own, and a body and query
 * a resolver has no business reading. Passing it back would re-expose precisely what the
 * package spent effort normalising, and would invite a resolver to make authorisation
 * decisions, which requirement 11 forbids.
 *
 * Upstream resolution needs exactly one thing the principal does not carry: the caller's
 * bearer credential. So that is what it gets, and nothing else. When something else turns
 * out to be genuinely required, adding a field here is a deliberate act with a reason
 * attached — which handing over the whole request would have skipped.
 *
 * ⚠️ `bearerToken` IS A LIVE CREDENTIAL. It is the caller's, it is valid, and it is being
 * handed to service-supplied code. Use it to authenticate the one upstream call that
 * resolves this principal. Do not log it, do not store it, do not forward it anywhere the
 * caller did not intend, and do not use it to act on the caller's behalf beyond resolution.
 */
export interface ResolverContext {
  /** The verified bearer token the caller sent, without the "Bearer " prefix. */
  bearerToken: string;
}

export type LocalIdentityResolver = (
  principal: Principal,
  context: ResolverContext,
) => unknown | null | Promise<unknown | null>;

export interface AuthClientOptions {
  /** Required. No default, ever: an unset base URL must be a construction failure, not a silent fallback to somebody's sandbox. */
  authServiceBaseUrl: string;
  /** Required. The package ships no implementation and refuses to construct without one. */
  isMemberOf: MembershipPredicate;
  /**
   * Optional. Supply it if this service resolves the caller to something of its own —
   * a local user row, or an upstream call made AS the caller.
   *
   * Its result is cached alongside the principal for the positive lifetime, which is the
   * reason to put resolution here rather than in a handler after `requireAuth`: resolving
   * outside the package means rebuilding that caching, and an uncached per-request call to
   * the auth service is the load hazard the negative cache exists to prevent.
   */
  resolveLocalIdentity?: LocalIdentityResolver;
  /** Introspection timeout. Not a security parameter. */
  timeoutMs?: number;
}

export interface AuthClient {
  requireAuth: RequestHandler;
  requireOrgMembership: RequestHandler;
  invalidate(token: string): void;
  clear(): void;
}

type Resolution =
  | { kind: 'verified'; principal: Principal }
  | { kind: 'refused' }
  | { kind: 'indeterminate'; reason: string };

/**
 * Every `x-user-*` header the caller sent is DELETED and the canonical ones re-set from
 * the verified principal. Substitute, never validate: validating still trusts the caller
 * to send something, and any path that skips the comparison restores the impersonation.
 *
 * The live Flutter client sends `x-user-identifier`; service_orbit_orgs writes
 * `x-user-id` after verifying and reads that downstream. Both are set here so a service
 * reading either gets the verified value. `x-user-idfr` was a forgeable header that
 * service_orbit_orgs has already removed -- deleting the whole prefix means a header
 * nobody has thought of yet cannot be smuggled past this either.
 */
function substituteUserHeaders(req: Request, principal: Principal): void {
  for (const name of Object.keys(req.headers)) {
    if (name.toLowerCase().startsWith('x-user-')) delete req.headers[name];
  }
  req.headers['x-user-id'] = principal.userId;
  req.headers['x-user-identifier'] = principal.userId;
}

/**
 * `internals` is a TEST SEAM and is not part of the supported options. It exists so the
 * conformance suite can drive the 60s and 5s lifetimes deterministically instead of
 * sleeping, and so those tests can fail. Production callers pass one argument.
 */
export function createAuthClient(
  options: AuthClientOptions,
  internals: { now?: () => number } = {},
): AuthClient {
  // Construction-time gates. A missing dependency is a startup crash, never a runtime
  // pass -- the failure mode this package exists to remove is a control that looks
  // present and binds nothing.
  if (!options || typeof options !== 'object') {
    throw new Error('createAuthClient: options are required');
  }
  if (typeof options.authServiceBaseUrl !== 'string' || options.authServiceBaseUrl === '') {
    throw new Error(
      'createAuthClient: authServiceBaseUrl is required. There is deliberately no default — ' +
        'a service that cannot reach the auth service must fail to start, not fall back.',
    );
  }
  if (typeof options.isMemberOf !== 'function') {
    throw new Error(
      'createAuthClient: isMemberOf is required. This package ships no membership ' +
        'implementation and will not construct without one. It must not default to true, ' +
        'and "no organisation sent" must not mean "no check" — see requireOrgMembership.',
    );
  }
  if (
    options.resolveLocalIdentity !== undefined &&
    typeof options.resolveLocalIdentity !== 'function'
  ) {
    throw new Error('createAuthClient: resolveLocalIdentity, when supplied, must be a function');
  }

  const baseUrl = options.authServiceBaseUrl.replace(/\/+$/, '');
  const timeoutMs = options.timeoutMs ?? 5_000;
  const { isMemberOf, resolveLocalIdentity } = options;

  // There is no stale mode. An expired entry must not be served even during an outage:
  // 60 seconds is the revocation reach, and serving past it silently extends it.
  const now = internals.now ?? Date.now;
  const positive = new TtlCache<Principal>(MAX_ENTRIES, POSITIVE_TTL_MS, now);
  const negative = new TtlCache<true>(MAX_ENTRIES, NEGATIVE_TTL_MS, now);
  const inFlight = new Map<string, Promise<Resolution>>();

  async function resolve(token: string): Promise<Resolution> {
    const warm = positive.get(token);
    if (warm) return { kind: 'verified', principal: warm };
    if (negative.get(token)) return { kind: 'refused' };

    const existing = inFlight.get(token);
    if (existing) return existing;

    const pending = (async (): Promise<Resolution> => {
      const outcome = await introspect(baseUrl, token, timeoutMs);

      if (outcome.kind === 'refused') {
        negative.set(token, true);
        return { kind: 'refused' };
      }

      if (outcome.kind === 'indeterminate') {
        // NEVER write the negative cache from an indeterminate result. A flapping auth
        // service would otherwise poison every credential it touches for 5 seconds at a
        // time, converting a partial outage into a total one.
        return outcome;
      }

      let principal: Principal = { userId: outcome.userId };

      if (resolveLocalIdentity) {
        let local: unknown;
        try {
          local = await resolveLocalIdentity(principal, { bearerToken: token });
        } catch {
          // The resolver's own dependency is down. That is not this credential being
          // bad, so it is indeterminate and is NOT negative-cached. The donor's
          // `catch {}` here is exactly what minted a fleet-wide identity of zero.
          return {
            kind: 'indeterminate',
            reason: 'local identity resolver failed',
          };
        }
        if (local === null || local === undefined) {
          // Verified principal, no local row. REFUSE. Never proceed as a placeholder
          // identity and never defer the decision to a downstream check.
          negative.set(token, true);
          return { kind: 'refused' };
        }
        principal = { userId: outcome.userId, local };
      }

      positive.set(token, principal);
      return { kind: 'verified', principal };
    })().finally(() => inFlight.delete(token));

    inFlight.set(token, pending);
    return pending;
  }

  const requireAuth: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers.authorization;
    if (typeof header !== 'string' || !header.startsWith('Bearer ') || header.length <= 7) {
      res.status(401).json({ error: 'missing_bearer_token' });
      return;
    }

    const result = await resolve(header.slice(7));

    if (result.kind === 'refused') {
      res.status(401).json({ error: 'invalid_token' });
      return;
    }

    if (result.kind === 'indeterminate') {
      // 503, not 401. The credential was never judged, and telling the user it is
      // invalid sends the app into a token refresh that cannot help.
      res.status(503).json({ error: 'auth_service_unavailable', detail: result.reason });
      return;
    }

    (req as Request & { principal?: Principal }).principal = result.principal;
    substituteUserHeaders(req, result.principal);
    next();
  };

  /**
   * Organisation membership. Mount this AFTER requireAuth on org-scoped routes only.
   *
   * The organisation headers are passed through completely untouched -- this handler
   * reads `x-org-id` and adds a verdict; it never sets, clears or derives organisation
   * context. The access token carries no organisation, so there is nothing to derive it
   * from, and substituting it would empty it on every request.
   *
   * Omitting the header is NOT a bypass: a route that asks for this check refuses when
   * no organisation is named.
   */
  const requireOrgMembership: RequestHandler = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    const principal = (req as Request & { principal?: Principal }).principal;
    if (!principal) {
      // Wiring error, not a caller error: requireOrgMembership without requireAuth.
      res.status(500).json({ error: 'auth_middleware_misordered' });
      return;
    }

    const raw = req.headers['x-org-id'];
    const organisationId = Array.isArray(raw) ? raw[0] : raw;
    if (typeof organisationId !== 'string' || organisationId.trim() === '') {
      res.status(403).json({ error: 'organisation_required' });
      return;
    }

    let member: boolean;
    try {
      member = await isMemberOf(principal, organisationId);
    } catch {
      res.status(503).json({ error: 'membership_check_unavailable' });
      return;
    }

    if (!member) {
      // 403, not 401. The credential is good and the action is not permitted; a 401
      // makes the app retry a refresh that cannot possibly help.
      res.status(403).json({ error: 'not_a_member_of_organisation' });
      return;
    }

    next();
  };

  return {
    requireAuth,
    requireOrgMembership,
    invalidate(token: string) {
      positive.delete(token);
      negative.delete(token);
    },
    clear() {
      positive.clear();
      negative.clear();
    },
  };
}
