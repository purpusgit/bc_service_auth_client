import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient } from '../src/index';

/*
 * The 60 seconds is a ceiling on how long a REVOKED credential keeps working. It was
 * also, accidentally, a floor on how long an EXPIRED one did: the entry was stamped a
 * flat 60s from the moment it was set and nothing carried the token's own `exp`.
 *
 * ⚠️ THE ASSERTION IS THE FETCH COUNT, not the verdict. A cache that simply dropped the
 * entry would also refuse, and so would one that never cached at all. What is asserted is
 * that the call actually REACHED THE AUTH SERVICE once the token's expiry passed — that
 * the cached verdict stopped standing in for it. The verdict is the consequence.
 *
 * The clock is driven through `internals.now`, the seam the conformance suite already
 * uses, because a test that sleeps through a 60-second window is a test nobody runs.
 */

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** A token shaped like the real thing: three segments, a JSON payload carrying `exp`. */
const tokenExpiringAt = (epochSeconds: number) =>
  `header.${b64url({ userId: 'u-1', exp: epochSeconds })}.signature`;

/** Stubs the auth service. Returns the spy so a test can count calls to it. */
function stubAuthService(respond: () => Response) {
  const spy = vi.fn(async () => respond());
  vi.stubGlobal('fetch', spy);
  return spy;
}

const verified = () =>
  new Response(JSON.stringify({ success: true, data: { userId: 'u-1' } }), { status: 200 });
const refused = () => new Response('', { status: 401 });

const clientOn = (now: () => number) =>
  createAuthClient({ authServiceBaseUrl: 'http://auth.test', isMemberOf: () => false }, { now });

describe('the positive cache never outlives the token it caches', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('stops serving a cached principal once the token has expired, inside the 60s window', async () => {
    let nowMs = 1_700_000_000_000;
    let reply = verified;
    const spy = stubAuthService(() => reply());
    const client = clientOn(() => nowMs);

    // Expires in 10 seconds — comfortably inside the 60-second window, which is the case
    // a flat lifetime got wrong.
    const token = tokenExpiringAt(Math.floor(nowMs / 1000) + 10);

    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    // Still inside its own life: the cache answers, the auth service is not asked again.
    nowMs += 5_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    // Past the token's `exp`, 11s into a 60s entry. Before the fix the cache answered
    // `verified` here and the auth service was never asked a second time.
    nowMs += 6_000;
    reply = refused;

    const afterExpiry = await client.verify(token);

    expect(spy).toHaveBeenCalledTimes(2);
    expect(afterExpiry.kind).toBe('refused');
  });

  it('does not extend a token with less life left than the skew floor', async () => {
    let nowMs = 1_700_000_000_000;
    let reply = verified;
    const spy = stubAuthService(() => reply());
    const client = clientOn(() => nowMs);

    // Two seconds of genuine life — less than the 5s skew floor. Applying that floor to
    // every token would cache this for 5s and serve it `verified` for 3s past its own
    // `exp`: the defect this file exists to close, just smaller. Every token passes
    // through this window on its way out, so it is the happy path rather than an edge.
    const token = tokenExpiringAt(Math.floor(nowMs / 1000) + 2);

    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    nowMs += 3_000;
    reply = refused;

    expect((await client.verify(token)).kind).toBe('refused');
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('throttles a token our clock thinks has expired but the auth service accepts', async () => {
    let nowMs = 1_700_000_000_000;
    const spy = stubAuthService(verified);
    const client = clientOn(() => nowMs);

    // Our clock runs 30s ahead of the auth service's, so this reads as expired here while
    // /token/validate still accepts it. Without the floor the entry is written
    // already-expired and, because the verdict was `verified`, nothing is negative-cached
    // either — so EVERY request re-introspects, unthrottled, against the estate's single
    // point of failure.
    const token = tokenExpiringAt(Math.floor(nowMs / 1000) - 30);

    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    nowMs += 4_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    // The floor is the refusal window, not the ceiling: skew must not buy a longer cache
    // than a refusal gets.
    nowMs += 2_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('still caches a token whose expiry is beyond the ceiling', async () => {
    let nowMs = 1_700_000_000_000;
    const spy = stubAuthService(verified);
    const client = clientOn(() => nowMs);

    // A 15-day token, which is what every live access token is today.
    const token = tokenExpiringAt(Math.floor(nowMs / 1000) + 15 * 24 * 60 * 60);

    expect((await client.verify(token)).kind).toBe('verified');
    nowMs += 59_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    // The ceiling still binds: 60s is the revocation reach and nothing may extend it.
    nowMs += 2_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('gives a token with no readable expiry the full ceiling, exactly as before', async () => {
    let nowMs = 1_700_000_000_000;
    const spy = stubAuthService(verified);
    const client = clientOn(() => nowMs);

    // Not a JWT at all. The estate's tokens are, but nothing in this package requires it,
    // and an opaque credential must not be refused for being opaque.
    const token = 'an-opaque-credential';

    expect((await client.verify(token)).kind).toBe('verified');
    nowMs += 59_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
