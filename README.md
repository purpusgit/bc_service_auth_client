# @purpusgit/service-auth-client

One shared implementation of `service_auth` token introspection, for every Node service in the estate.

It is deliberately small, has **zero runtime dependencies**, and refuses to start if it is wired up wrongly.

```ts
import { createAuthClient } from '@purpusgit/service-auth-client';

const auth = createAuthClient({
  authServiceBaseUrl: process.env.AUTH_SERVICE_BASE_URL!,   // required; no default, ever
  isMemberOf: (principal, orgId) => membership.check(principal.userId, orgId),
  resolveLocalIdentity: (p) => users.findByIdentifier(p.userId), // optional
});

router.get('/things', auth.requireAuth, handler);                        // signed-in
router.get('/org/things', auth.requireAuth, auth.requireOrgMembership, h); // org-scoped
```

---

## What it does, and the one thing it must never do

| | |
|---|---|
| Verifies | by **introspection** against `service_auth`. It never holds a signing key. |
| Decides | **nothing about authorisation.** Whether this principal may perform this action is the service's question. |

The single exception is the membership predicate, and it is deliberately the narrowest one possible: it answers *is this principal in this organisation*, never *may they do this*.

---

## The principal is substituted. The organisation is validated.

**This distinction is the whole design and getting it backwards breaks the live app.**

**Principal — substituted.** The verified subject is attached as `req.principal`, and **every `x-user-*` header the caller sent is deleted and the canonical ones re-set** from the verified value. Validating a client-supplied identity still trusts the caller to send something, and any path that skips the comparison restores the impersonation.

**Organisation — validated, never substituted.** The caller keeps sending organisation context exactly as it does today; the package reads it, checks membership, and **passes every organisation header through byte-identical**. It never sets, clears or derives organisation context.

**Why it cannot be otherwise:** the access token carries `{ userId }` and nothing else — verified by reading the signing call in `service_auth` (`jwt.util.ts`, `const payload: TokenPayload = { userId }`), not a document about it. **There is no organisation in the token to re-establish anything from.** A package that "sets" organisation context would set it to empty on every request and fail every organisation-scoped screen in the live Flutter app.

### The three organisation headers

The live client sends **three**, on both mobile and web: `x-org-id`, `x-org-identifier`, `x-org-short-name`.

**Only `x-org-id` is validated**, because that is the one services actually scope on (`service_orbit_orgs` parses it as a positive integer and puts it in the SQL predicate; nothing reads `x-org-identifier`). **All three are passed through untouched.**

> ⚠️ **Known limitation.** A service that scopes on `x-org-short-name` or `x-org-identifier` **instead of** `x-org-id` is not protected by this package: a caller could send their own `x-org-id` alongside another organisation's short name. Validating those too needs a resolver that maps them to an organisation, which is authorisation-shaped and is not in this package. **If your service scopes on anything other than `x-org-id`, say so before adopting.**

---

## The three response classes

Two is not enough, and that is not a theoretical point — it is the defect this estate has already shipped twice.

| Upstream | Class | Cached |
|---|---|---|
| `2xx` carrying a `userId` | **verified** | 60s |
| **`401` and only `401`** | **refused** | 5s |
| transport failure, timeout, **5xx**, `429`, malformed `2xx` | **indeterminate** | **never, in either cache** |

**Indeterminate serves only from within the unexpired 60-second cache, and otherwise refuses as itself — `503`, never `401`.** Telling a user their credential is invalid when the auth service is down sends the app into a token refresh that cannot help.

**Why `5xx` is not "unreachable":** `manageUserAuthorization` in `service_auth` answers **500 when its own database is down**. The auth service is reachable and replying, so a two-way reachable/unreachable split classifies that as reachable, and therefore as a refusal — reporting a database outage to every user as a bad credential and poisoning the negative cache while it flaps.

---

## Revocation, and the 60 seconds

**Read this before adopting.** It is the honest account of what this package does and does not close.

`/token/validate` does more than check a signature: it requires a **live row in `purpus_auth.session_info` for that exact token**, and signing out deletes that row. **So revocation at the auth service is immediate.**

The only place a signed-out credential survives is **this package's positive cache, for at most 60 seconds**. That 60 seconds *is* the revocation reach. It is a security parameter, not a tuning knob, and it is **deliberately not configurable**.

**`invalidate(token)` and `clear()` are exported so the conformance suite can drive the cache.** Nothing in the estate currently calls `invalidate` from a sign-out, and **it is important that you know that rather than assuming the method's existence means the window is closed.** Closing it properly needs a revocation channel — a shared cache or a broadcast from the auth service to every running service — which **does not exist in this estate and is not this package's job**.

> **One user-visible consequence.** `session_info.last_seen` is updated on each introspection and is surfaced in the device/session list. With a 60-second cache that timestamp can be **up to a minute stale**. Cosmetic, not a security property — recorded here so it is not discovered as a bug report.

---

## Never a default identity

If a principal verifies but **cannot be resolved to a local row**, the request is **refused**. Not passed on as a placeholder, not deferred to a downstream check, not cached as a positive.

> ⚠️ **This is a behaviour change from the donor, and `service_nearyest` will change behaviour the day it adopts.** Its current middleware leaves the local id as `0` when the lookup fails or returns nothing, proceeds authenticated, and relies on a downstream check to reject. **Requests that used to proceed as identity zero will now refuse.** That is the fix, not a regression — but the timing is yours to choose.
>
> A `purpus_user` outage under the donor mints a **60-second fleet-wide session as identity zero for every caller at once**. That is what this closes.

**Resolver failures and missing rows are different states.** A resolver that **returns null** means the principal genuinely has no local row → refused, negative-cached for 5s. A resolver that **throws** means its own dependency is down → indeterminate, `503`, **never negative-cached**. Collapsing the two is exactly the donor's `catch {}`.

**Absent resolver ≠ unresolvable principal.** A service with no local user table simply omits `resolveLocalIdentity`, and nothing is refused for that reason.

---

## Why refusals are cached, and why it is not about you

Caching refusals for 5 seconds is **load-bearing for the auth service's survival, not a nicety for the caller**.

Every cache miss costs `/token/validate` a database **read and a write** (`UPDATE session_info SET last_seen`), and it is the single point of failure for every signed-in request in the estate. **Thirteen services adopting an uncached-refusal client would turn any credential-stuffing flood into an estate-wide outage.**

5 seconds rather than 60 because a long negative cache makes a restored session wait.

---

## Construction fails loudly

The package **refuses to construct** without `authServiceBaseUrl` or without `isMemberOf`. There is no default membership predicate, it never falls back to `true`, and *"no organisation was sent"* never means *"no check"* — `requireOrgMembership` refuses when no organisation is named, so omitting the header is not a bypass.

A missing dependency is a startup crash, never a runtime pass. The failure mode this package exists to remove is a control that looks present and binds nothing.

---

## Marking a route public

**There is no `public: true` flag, on purpose.** Put unauthenticated routes in their own router, mounted outside every gated one:

```ts
app.use('/api/public', publicRouter);        // no requireAuth anywhere inside
app.use('/api', auth.requireAuth, apiRouter);
```

This is the donor's shape and it is better than a per-route flag: a deliberate exemption is a *file you had to create*, not a word someone forgot to type. Pair it with a CI route-coverage check that fails on any route outside the public router without `requireAuth`.

---

## Not in scope

- **A Fastify wrapper.** Both Fastify services are TypeScript; a thin wrapper is roughly half a day and is not written yet.
- **A Python implementation.** Phase two, deferred by founder ruling.
- **Adoption by any service.** This package is built, not rolled out. No service is wired to it.

## Notes

- **Node ≥ 18** — uses native `fetch` and `AbortSignal.timeout`, so there is no HTTP dependency.
- Compiled to **CommonJS**, which both the CommonJS services and the ESM ones can consume.
- `createAuthClient` takes a second `internals` argument used only by the conformance suite to drive the clock. Production callers pass one argument.
