/**
 * THE SHARED CASE TABLE. One table, two thin drivers — deliberately not one harness.
 *
 * The cases that prove the Express adapter must prove the Fastify one, because they are two
 * faces of the same core. But forcing a single HTTP driver across both frameworks would build
 * an abstraction with two consumers and no other purpose, which is the shape this stream keeps
 * deleting. So the TABLE is shared and each driver is ~20 lines of framework-specific wiring.
 *
 * `mode` drives the stubbed auth service; each driver stands one up the same way.
 */
export type StubMode = 'ok' | '401' | '500' | '429' | 'garbage' | 'unreachable';

export interface AuthCase {
  name: string;
  mode: StubMode;
  /** Authorization header to send, or none. */
  token?: string;
  /** Extra headers the caller sends. */
  headers?: Record<string, string>;
  expectStatus: number;
  /** Assert on the decorated principal the handler saw, when the request got that far. */
  expectPrincipal?: string | null;
  /** Headers the handler must see EXACTLY as sent (organisation context is never substituted). */
  expectPassthrough?: Record<string, string>;
  /** Headers the adapter must have overwritten (the principal is substituted, never validated). */
  expectOverwritten?: Record<string, string>;
  /** Headers the adapter must have DELETED outright — the whole x-user-* prefix, not just the known names. */
  expectAbsent?: string[];
}

export const AUTH_CASES: AuthCase[] = [
  { name: 'no bearer token is refused',
    mode: 'ok', expectStatus: 401, expectPrincipal: null },

  { name: 'a verified token reaches the handler with its principal',
    mode: 'ok', token: 'tok-1', expectStatus: 200, expectPrincipal: 'u-1' },

  { name: 'a refused credential is 401',
    mode: '401', token: 'bad', expectStatus: 401, expectPrincipal: null },

  { name: 'an auth service 500 is 503, NOT 401 — the credential was never judged',
    mode: '500', token: 'x1', expectStatus: 503, expectPrincipal: null },

  { name: 'a rate-limited auth service is 503, not a bad credential',
    mode: '429', token: 'x2', expectStatus: 503, expectPrincipal: null },

  { name: 'an unparseable 2xx is indeterminate, not a refusal',
    mode: 'garbage', token: 'x3', expectStatus: 503, expectPrincipal: null },

  { name: 'an unreachable auth service is 503',
    mode: 'unreachable', token: 'x4', expectStatus: 503, expectPrincipal: null },

  { name: 'organisation headers reach the handler byte-identical',
    mode: 'ok', token: 'tok-2', expectStatus: 200, expectPrincipal: 'u-1',
    headers: { 'x-org-id': '4242', 'x-org-identifier': 'ORG-abc', 'x-org-short-name': 'japa' },
    expectPassthrough: { 'x-org-id': '4242', 'x-org-identifier': 'ORG-abc', 'x-org-short-name': 'japa' } },

  { name: 'a forged x-user-* header is overwritten with the verified principal',
    mode: 'ok', token: 'tok-3', expectStatus: 200, expectPrincipal: 'u-1',
    // x-user-idfr is here deliberately. The two canonical names are re-set explicitly by the
    // adapters, so a case sending only those passes even if the delete-the-whole-prefix loop
    // is removed — which a mutation proved. This third header is only cleared by that loop,
    // so it is what actually tests it.
    headers: { 'x-user-id': 'victim', 'x-user-identifier': 'victim', 'x-user-idfr': '99' },
    expectOverwritten: { 'x-user-id': 'u-1', 'x-user-identifier': 'u-1' },
    expectAbsent: ['x-user-idfr'] },
];
