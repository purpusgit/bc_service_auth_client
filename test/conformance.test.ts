/**
 * The conformance suite. One test per failure this estate has actually had.
 *
 * These run against a REAL stubbed auth service on a real socket, not a mocked fetch,
 * so the three-way classification is exercised through the same code path production
 * uses. A test that stubs the thing under test proves the stub.
 */
import express from 'express';
import request from 'supertest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient, TtlCache, type Principal } from '../src/index';

// ---------------------------------------------------------------- stub auth service

type Mode = 'ok' | '401' | '500' | '429' | 'slow' | 'garbage' | 'ok-without-userid';

let mode: Mode = 'ok';
let upstreamCalls = 0;
let authServer: http.Server;
let authBaseUrl: string;

beforeAll(async () => {
  authServer = http.createServer((req, res) => {
    upstreamCalls += 1;
    const send = (code: number, body: unknown) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    switch (mode) {
      case '401': return send(401, { success: false, message: 'Unauthorized: Invalid token' });
      case '500': return send(500, { success: false, message: 'Internal server error' });
      case '429': return send(429, { success: false, message: 'Too many requests' });
      case 'garbage':
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('<html>not json</html>');
      case 'ok-without-userid': return send(200, { success: true, data: {} });
      case 'slow': return setTimeout(() => send(200, { success: true, data: { userId: 'u-1' } }), 300);
      default: return send(200, { success: true, data: { userId: 'u-1' } });
    }
  });
  await new Promise<void>((r) => authServer.listen(0, '127.0.0.1', r));
  authBaseUrl = `http://127.0.0.1:${(authServer.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => authServer.close(() => r())));

beforeEach(() => { mode = 'ok'; upstreamCalls = 0; });

// ---------------------------------------------------------------- app under test

function buildApp(
  opts: Partial<Parameters<typeof createAuthClient>[0]> = {},
  clock?: { nowMs: number },
) {
  const client = createAuthClient(
    {
      authServiceBaseUrl: authBaseUrl,
      isMemberOf: async () => true,
      timeoutMs: 100,
      ...opts,
    } as Parameters<typeof createAuthClient>[0],
    clock ? { now: () => clock.nowMs } : {},
  );

  const app = express();
  app.get('/private', client.requireAuth, (req, res) => {
    res.json({
      principal: (req as express.Request & { principal?: Principal }).principal,
      // echoed so a test can assert what the HANDLER saw, not what the client sent
      seenHeaders: req.headers,
    });
  });
  app.get('/org', client.requireAuth, client.requireOrgMembership, (req, res) => {
    res.json({ seenHeaders: req.headers });
  });
  return { app, client };
}

const bearer = (t = 'tok-1') => ({ Authorization: `Bearer ${t}` });

// ---------------------------------------------------------------- the suite

describe('the package never accepts what the auth service refused', () => {
  it('refuses a token the auth service refuses, and never independently accepts one', async () => {
    mode = '401';
    const { app } = buildApp();
    const res = await request(app).get('/private').set(bearer());
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
  });

  it('refuses when no bearer token is present at all', async () => {
    const { app } = buildApp();
    expect((await request(app).get('/private')).status).toBe(401);
    expect((await request(app).get('/private').set({ Authorization: 'Bearer ' })).status).toBe(401);
  });
});

describe('a bad credential and an unreachable auth service are DIFFERENT', () => {
  it('401 upstream -> 401 invalid_token', async () => {
    mode = '401';
    const { app } = buildApp();
    const res = await request(app).get('/private').set(bearer());
    expect(res.status).toBe(401);
  });

  it('transport failure -> 503, NOT 401', async () => {
    const { app } = buildApp({ authServiceBaseUrl: 'http://127.0.0.1:1' });
    const res = await request(app).get('/private').set(bearer());
    expect(res.status).toBe(503);
    expect(res.body.error).toBe('auth_service_unavailable');
  });

  it('timeout -> 503, NOT 401', async () => {
    mode = 'slow';
    const { app } = buildApp({ timeoutMs: 50 });
    const res = await request(app).get('/private').set(bearer());
    expect(res.status).toBe(503);
  });

  it('an unreachable auth service never serves an expired entry', async () => {
    // SAME client throughout, with a driven clock. The first version of this test built a
    // SECOND client whose cache was cold, so it returned 503 whether or not expiry worked
    // — it passed against broken code and guarded nothing.
    const clock = { nowMs: 1_000_000 };
    const { app } = buildApp({}, clock);

    expect((await request(app).get('/private').set(bearer('warm'))).status).toBe(200);
    expect(upstreamCalls).toBe(1);

    // inside the 60s window with the auth service now failing: served from the warm entry
    clock.nowMs += 59_000;
    mode = '500';
    expect((await request(app).get('/private').set(bearer('warm'))).status).toBe(200);
    expect(upstreamCalls).toBe(1); // never left the cache

    // past 60s: the entry is gone and an unreachable auth service refuses AS ITSELF
    clock.nowMs += 2_000;
    expect((await request(app).get('/private').set(bearer('warm'))).status).toBe(503);
  });

  it('control: that expiry assertion is capable of failing', () => {
    let t = 0;
    const c = new TtlCache<string>(10, 60_000, () => t);
    c.set('k', 'v');
    expect(c.get('k')).toBe('v');   // present before expiry
    t = 60_001;
    expect(c.get('k')).toBeUndefined(); // absent after — this is what the test above relies on
  });
});

describe('an auth service 500 is not a bad credential and does not poison the cache', () => {
  it('500 -> 503, and the NEGATIVE cache is not written', async () => {
    const { app } = buildApp();
    mode = '500';
    expect((await request(app).get('/private').set(bearer('flap'))).status).toBe(503);

    // If 500 had been cached as a refusal, this would answer 401 from cache without
    // ever reaching upstream. It must reach upstream and succeed.
    mode = 'ok';
    const res = await request(app).get('/private').set(bearer('flap'));
    expect(res.status).toBe(200);
  });

  it('429 and a malformed 2xx are also indeterminate, not refusals', async () => {
    const { app } = buildApp();
    mode = '429';
    expect((await request(app).get('/private').set(bearer('a'))).status).toBe(503);
    mode = 'garbage';
    expect((await request(app).get('/private').set(bearer('b'))).status).toBe(503);
    mode = 'ok-without-userid';
    expect((await request(app).get('/private').set(bearer('c'))).status).toBe(503);
  });
});

describe('caching', () => {
  it('N concurrent requests on one credential produce EXACTLY ONE upstream call', async () => {
    const { app } = buildApp({ timeoutMs: 2_000 }); // stub sleeps 300ms; must outlast it
    mode = 'slow';
    const results = await Promise.all(
      Array.from({ length: 25 }, () => request(app).get('/private').set(bearer('burst'))),
    );
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(upstreamCalls).toBe(1);
  });

  it('a refusal is served from the negative cache, and re-checked after 5 seconds', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'performance'] });
    try {
      const { app } = buildApp();
      mode = '401';
      expect((await request(app).get('/private').set(bearer('bad'))).status).toBe(401);
      expect(upstreamCalls).toBe(1);

      // within 5s: served from the negative cache, no second upstream call
      expect((await request(app).get('/private').set(bearer('bad'))).status).toBe(401);
      expect(upstreamCalls).toBe(1);

      vi.advanceTimersByTime(5_100);
      mode = 'ok';
      expect((await request(app).get('/private').set(bearer('bad'))).status).toBe(200);
      expect(upstreamCalls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('never a default identity', () => {
  it('a principal that verifies but resolves to NO local row is REFUSED', async () => {
    const { app } = buildApp({ resolveLocalIdentity: async () => null });
    const res = await request(app).get('/private').set(bearer());
    expect(res.status).toBe(401);
    expect(res.body.principal).toBeUndefined();
  });

  it('that refusal is NOT cached as a positive', async () => {
    const { app } = buildApp({ resolveLocalIdentity: async () => null });
    await request(app).get('/private').set(bearer('nolocal'));
    const again = await request(app).get('/private').set(bearer('nolocal'));
    expect(again.status).toBe(401);
  });

  it('a resolver whose own dependency is DOWN is 503, not a refusal and not identity zero', async () => {
    const { app } = buildApp({
      resolveLocalIdentity: async () => { throw new Error('purpus_user unreachable'); },
    });
    const res = await request(app).get('/private').set(bearer('dbdown'));
    expect(res.status).toBe(503);
  });

  it('no resolver supplied is a DIFFERENT state from an unresolvable principal', async () => {
    const { app } = buildApp(); // no resolveLocalIdentity
    const res = await request(app).get('/private').set(bearer());
    expect(res.status).toBe(200);
    expect(res.body.principal.userId).toBe('u-1');
    expect(res.body.principal.local).toBeUndefined();
  });
});

describe('construction gates', () => {
  it('CANNOT be constructed without a membership predicate', () => {
    expect(() =>
      createAuthClient({ authServiceBaseUrl: authBaseUrl } as never),
    ).toThrow(/isMemberOf is required/);
  });

  it('cannot be constructed without an auth service base url', () => {
    expect(() =>
      createAuthClient({ isMemberOf: () => true } as never),
    ).toThrow(/authServiceBaseUrl is required/);
  });

  it('does not accept a non-function membership predicate', () => {
    expect(() =>
      createAuthClient({ authServiceBaseUrl: authBaseUrl, isMemberOf: true } as never),
    ).toThrow(/isMemberOf is required/);
  });
});

describe('organisation context is validated, never substituted', () => {
  it('arrives at the handler BYTE-IDENTICAL to what the caller sent', async () => {
    const { app } = buildApp();
    const sent = {
      'x-org-id': '4242',
      'x-org-identifier': 'ORG-UUID-abc',
      'x-org-short-name': 'japa',
    };
    const res = await request(app).get('/org').set(bearer()).set(sent);
    expect(res.status).toBe(200);
    expect(res.body.seenHeaders['x-org-id']).toBe('4242');
    expect(res.body.seenHeaders['x-org-identifier']).toBe('ORG-UUID-abc');
    expect(res.body.seenHeaders['x-org-short-name']).toBe('japa');
  });

  it('a non-member is 403, not 401', async () => {
    const { app } = buildApp({ isMemberOf: async () => false });
    const res = await request(app).get('/org').set(bearer()).set({ 'x-org-id': '4242' });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('not_a_member_of_organisation');
  });

  it('omitting the organisation header is NOT a bypass', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/org').set(bearer());
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('organisation_required');
  });

  it('the predicate receives the VERIFIED principal and the org the caller named', async () => {
    const seen: Array<[Principal, string]> = [];
    const { app } = buildApp({
      isMemberOf: async (p, org) => { seen.push([p, org]); return true; },
    });
    await request(app).get('/org').set(bearer()).set({ 'x-org-id': '4242' });
    expect(seen).toHaveLength(1);
    expect(seen[0]![0].userId).toBe('u-1');
    expect(seen[0]![1]).toBe('4242');
  });

  it('a membership store that is DOWN is 503, not a denial', async () => {
    const { app } = buildApp({
      isMemberOf: async () => { throw new Error('membership db down'); },
    });
    const res = await request(app).get('/org').set(bearer()).set({ 'x-org-id': '4242' });
    expect(res.status).toBe(503);
  });
});

describe('the principal is substituted, never validated', () => {
  it('a forged x-user-* header is OVERWRITTEN with the verified principal', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .get('/private')
      .set(bearer())
      .set({ 'x-user-id': 'victim', 'x-user-identifier': 'victim', 'x-user-idfr': '99' });
    expect(res.status).toBe(200);
    expect(res.body.seenHeaders['x-user-id']).toBe('u-1');
    expect(res.body.seenHeaders['x-user-identifier']).toBe('u-1');
    // the whole forgeable prefix is dropped, not just the two names we know about
    expect(res.body.seenHeaders['x-user-idfr']).toBeUndefined();
  });
});

describe('invalidate and clear exist so the suite can drive the cache', () => {
  it('invalidate drops a warm entry', async () => {
    const { app, client } = buildApp();
    expect((await request(app).get('/private').set(bearer('inv'))).status).toBe(200);
    expect(upstreamCalls).toBe(1);
    await request(app).get('/private').set(bearer('inv'));
    expect(upstreamCalls).toBe(1); // served warm

    client.invalidate('inv');
    await request(app).get('/private').set(bearer('inv'));
    expect(upstreamCalls).toBe(2); // re-introspected
  });
});

describe('the resolver context — upstream resolution, and only what it needs', () => {
  it('receives the CALLER\'S OWN bearer token, not some other one', async () => {
    const seen: Array<{ userId: string; token: string }> = [];
    const { app } = buildApp({
      resolveLocalIdentity: async (p: Principal, ctx: { bearerToken: string }) => {
        seen.push({ userId: p.userId, token: ctx.bearerToken });
        return { id: 1 };
      },
    });
    await request(app).get('/private').set(bearer('caller-alpha'));
    await request(app).get('/private').set(bearer('caller-beta'));
    expect(seen.map((s) => s.token)).toEqual(['caller-alpha', 'caller-beta']);
  });

  it('the context carries the token and NOTHING else — no request, no headers', async () => {
    let keys: string[] = [];
    const { app } = buildApp({
      resolveLocalIdentity: async (_p: Principal, ctx: object) => {
        keys = Object.keys(ctx);
        return { id: 1 };
      },
    });
    await request(app).get('/private').set(bearer()).set({ 'x-org-id': '99', 'x-user-id': 'forged' });
    // If this ever grows, it should be a deliberate act with a reason, not a drift.
    expect(keys).toEqual(['bearerToken']);
  });

  it('the resolver result is CACHED with the principal — repeated requests call it once', async () => {
    let resolverCalls = 0;
    const { app } = buildApp({
      resolveLocalIdentity: async () => { resolverCalls += 1; return { id: 7 }; },
    });
    for (let i = 0; i < 5; i += 1) {
      expect((await request(app).get('/private').set(bearer('warm-resolver'))).status).toBe(200);
    }
    // This is the whole reason resolution belongs inside the package: resolving outside it
    // means rebuilding this caching in every adopting service.
    expect(resolverCalls).toBe(1);
    expect(upstreamCalls).toBe(1);
  });

  it('a burst on one credential calls the resolver exactly once', async () => {
    let resolverCalls = 0;
    mode = 'slow';
    const { app } = buildApp({
      timeoutMs: 2_000,
      resolveLocalIdentity: async () => { resolverCalls += 1; return { id: 7 }; },
    });
    await Promise.all(Array.from({ length: 20 }, () => request(app).get('/private').set(bearer('burst2'))));
    expect(resolverCalls).toBe(1);
  });

  it('an OLD one-argument resolver still works — adding the context is not a breaking change', async () => {
    const { app } = buildApp({ resolveLocalIdentity: async (p: Principal) => ({ echoed: p.userId }) });
    const res = await request(app).get('/private').set(bearer());
    expect(res.status).toBe(200);
    expect(res.body.principal.local).toEqual({ echoed: 'u-1' });
  });

  it('a resolver that uses the token to fail still refuses rather than passing', async () => {
    const { app } = buildApp({
      resolveLocalIdentity: async (_p: Principal, ctx: { bearerToken: string }) =>
        (ctx.bearerToken === 'no-row' ? null : { id: 1 }),
    });
    expect((await request(app).get('/private').set(bearer('no-row'))).status).toBe(401);
    expect((await request(app).get('/private').set(bearer('has-row'))).status).toBe(200);
  });
});
