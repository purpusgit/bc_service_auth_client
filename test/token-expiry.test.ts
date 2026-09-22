import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient } from '../src/index';

/*
 * The 60 seconds is a ceiling on how long a REVOKED credential keeps working. It was
 * also, accidentally, a floor on how long an EXPIRED one did: the entry was stamped a
 * flat 60s from the moment it was set and `Principal` carried no expiry, so a token
 * cached one second before its own `exp` was served as verified for a further 59
 * seconds after expiring.
 *
 * ⚠️ THE ASSERTION IS NOT "the second call refuses". A cache that simply dropped the
 * entry would also refuse here, and so would one that never cached at all. What is
 * asserted is that the SECOND CALL REACHED THE AUTH SERVICE -- that the cached verdict
 * stopped standing in for it once the token's own expiry passed. The fetch count is
 * therefore the real assertion and the verdict is the consequence.
 *
 * The clock is driven through `internals.now`, the seam the conformance suite already
 * uses, because a test that sleeps for a 60-second window is a test nobody runs.
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

describe('the positive cache never outlives the token it caches', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('stops serving a cached principal once the token has expired, inside the 60s window', async () => {
    let nowMs = 1_700_000_000_000;
    let reply = verified;
    const spy = stubAuthService(() => reply());

    const client = createAuthClient(
      { authServiceBaseUrl: 'http://auth.test', isMemberOf: () => false },
      { now: () => nowMs },
    );

    // The token expires in 10 seconds — comfortably inside the 60-second positive window,
    // which is the case the flat lifetime got wrong.
    const token = tokenExpiringAt(Math.floor(nowMs / 1000) + 10);

    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    // Still inside its own life: the cache answers and the auth service is not asked again.
    nowMs += 5_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);

    // Now past the token's `exp`, but only 11s into a 60s entry. Before the fix the cache
    // answered `verified` here and the auth service was never asked a second time.
    nowMs += 6_000;
    reply = refused;

    const afterExpiry = await client.verify(token);

    expect(spy).toHaveBeenCalledTimes(2);
    expect(afterExpiry.kind).toBe('refused');
  });

  it('still caches a token whose expiry is beyond the ceiling', async () => {
    let nowMs = 1_700_000_000_000;
    const spy = stubAuthService(verified);

    const client = createAuthClient(
      { authServiceBaseUrl: 'http://auth.test', isMemberOf: () => false },
      { now: () => nowMs },
    );

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

    const client = createAuthClient(
      { authServiceBaseUrl: 'http://auth.test', isMemberOf: () => false },
      { now: () => nowMs },
    );

    // Not a JWT at all. The estate's service tokens are, but nothing in this package
    // requires it, and an opaque credential must not be refused for being opaque.
    const token = 'an-opaque-credential';

    expect((await client.verify(token)).kind).toBe('verified');
    nowMs += 59_000;
    expect((await client.verify(token)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
