/**
 * The three-way classifier. This is the security core of the package and the reason
 * it exists as one implementation rather than thirteen.
 *
 * The donor (service_nearyest) collapsed every failure into a single `null` with
 * `.catch(() => null)`, so a 401, a connection timeout, a refused connection and an
 * upstream 500 were indistinguishable, and all four were reported to the caller as
 * "Invalid token". That refusal is safe but the diagnosis is a lie, and it is the same
 * defect class as the 500-instead-of-401 already fixed in service_mongo_social.
 *
 * Three classes, because two is not enough:
 *
 *   verified       2xx carrying a userId.        -> cache 60s
 *   refused        401 and ONLY 401.             -> cache 5s
 *   indeterminate  transport failure, timeout,
 *                  5xx, 429, or a malformed 2xx. -> NEVER cached, either way
 *
 * Why 5xx is not "unreachable": `manageUserAuthorization` in service_auth answers 500
 * when its OWN database is down. The auth service is reachable and replying, so a
 * two-way reachable/unreachable split classifies that as "reachable" and therefore as a
 * refusal — reporting a database outage to every user as a bad credential, and poisoning
 * the negative cache for 5 seconds per token while it flaps.
 */

export type Introspection =
  | { kind: 'verified'; userId: string }
  | { kind: 'refused' }
  | { kind: 'indeterminate'; reason: string };

export async function introspect(
  authServiceBaseUrl: string,
  token: string,
  timeoutMs: number,
): Promise<Introspection> {
  let res: Response;

  try {
    res = await fetch(`${authServiceBaseUrl}/token/validate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    // DNS failure, connection refused, TLS failure, abort on timeout. The auth service
    // did not answer, so nothing is known about this credential.
    const reason = err instanceof Error ? err.name : 'transport failure';
    return { kind: 'indeterminate', reason: `auth service did not answer (${reason})` };
  }

  // 401 is the ONLY status that means "this credential is bad". A 403 means the auth
  // service refused us, the caller — that is our configuration problem, not the user's.
  if (res.status === 401) return { kind: 'refused' };

  if (!res.ok) {
    return { kind: 'indeterminate', reason: `auth service answered ${res.status}` };
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return { kind: 'indeterminate', reason: 'auth service returned an unparseable body' };
  }

  // service_auth /token/validate answers { success, message, data: { userId } }.
  const userId = (body as { data?: { userId?: unknown } })?.data?.userId;

  if (typeof userId !== 'string' || userId === '') {
    // A 2xx with no principal in it is an upstream contract break, not a bad credential.
    // Refusing it as "invalid token" would blame the user for our own regression.
    return { kind: 'indeterminate', reason: 'auth service returned 2xx without a userId' };
  }

  return { kind: 'verified', userId };
}
