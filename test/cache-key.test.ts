import { createHash } from 'crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TtlCache, cacheKey, createAuthClient } from '../src/index';

/*
 * Both caches, and the single-flight map, are keyed on SHA-256(token), never the bearer token
 * itself (AUTH-01 order 5, specs#312 6387624126). A heap dump, a debugger or a future "log the
 * cache" line must not hold a usable credential.
 *
 * ⚠️ THE ASSERTION IS ON EVERY KEY THE CACHE SEES, not on a verdict: a client that keyed on the
 * raw token answers exactly the same, so only watching the keys can fail.
 */

const TOKEN = 'header.eyJ1c2VySWQiOiJ1LTEifQ.signature-secret-part';
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

function stubAuthService(status: number) {
  const spy = vi.fn(async () =>
    status === 200
      ? new Response(JSON.stringify({ success: true, data: { userId: 'u-1' } }), { status: 200 })
      : new Response('', { status }),
  );
  vi.stubGlobal('fetch', spy);
  return spy;
}

const client = () => createAuthClient({ authServiceBaseUrl: 'http://auth.test', isMemberOf: () => false });

function watchKeys() {
  const keys: string[] = [];
  for (const m of ['get', 'set', 'delete'] as const) {
    const real = TtlCache.prototype[m] as (...a: unknown[]) => unknown;
    vi.spyOn(TtlCache.prototype, m).mockImplementation(function (this: unknown, ...a: unknown[]) {
      keys.push(String(a[0]));
      return real.apply(this, a);
    } as never);
  }
  return keys;
}

describe('cache keys are SHA-256(token), never the token', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('cacheKey is the hex SHA-256 of the token', () => {
    expect(cacheKey(TOKEN)).toBe(sha(TOKEN));
    expect(cacheKey(TOKEN)).toMatch(/^[0-9a-f]{64}$/);
  });

  it.each([
    ['verified (positive cache)', 200],
    ['refused (negative cache)', 401],
  ])('%s: every get and set key is the hash, and no key contains the token or any part of it', async (_n, status) => {
    stubAuthService(status);
    const keys = watchKeys();
    const c = client();
    await c.verify(TOKEN);
    await c.verify(TOKEN);
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      expect(k).toBe(sha(TOKEN));
      for (const part of TOKEN.split('.')) expect(k).not.toContain(part);
    }
  });

  it('the cache still works through the hash: a warm token is not re-introspected', async () => {
    const spy = stubAuthService(200);
    const c = client();
    await c.verify(TOKEN);
    await c.verify(TOKEN);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('two tokens never share an entry', async () => {
    const spy = stubAuthService(200);
    const c = client();
    await c.verify(TOKEN);
    await c.verify(`${TOKEN}x`);
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('invalidate(token) drops the hashed entry, so the next call reaches the auth service', async () => {
    const spy = stubAuthService(200);
    const keys = watchKeys();
    const c = client();
    await c.verify(TOKEN);
    c.invalidate(TOKEN);
    await c.verify(TOKEN);
    expect(spy).toHaveBeenCalledTimes(2);
    expect(keys.every((k) => k === sha(TOKEN))).toBe(true);
  });

  it('concurrent calls for one token share one introspection (single flight keyed on the hash)', async () => {
    const spy = stubAuthService(200);
    const c = client();
    await Promise.all([c.verify(TOKEN), c.verify(TOKEN), c.verify(TOKEN)]);
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
