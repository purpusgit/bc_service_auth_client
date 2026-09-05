# @purpusgit/service-auth-client

One shared implementation of `service_auth` token introspection, for every Node service in the estate.

It is deliberately small, has **zero runtime dependencies**, and refuses to start if it is wired up wrongly.

```ts
import { createAuthClient } from '@purpusgit/service-auth-client';

const auth = createAuthClient({
  authServiceBaseUrl: process.env.AUTH_SERVICE_BASE_URL!,   // required; no default, ever
  isMemberOf: () => false,   // see "Membership is not implemented" — every service passes this today
  resolveLocalIdentity: (p) => users.findByIdentifier(p.userId), // optional
});

router.get('/things', auth.requireAuth, handler);                        // signed-in
router.get('/org/things', auth.requireAuth, auth.requireOrgMembership, h); // org-scoped
```

---

## Before you adopt — answer these four, in the pull request

**Not a formality.** Each one has a wrong answer that produces a service which *looks* protected and is not. Answer them in the adopting PR so a reviewer can see the answers rather than reconstruct them.

### 1. Which organisation header does this service scope on?

**`x-org-id` is the only one this package validates.** The live client sends three — `x-org-id`, `x-org-identifier` and `x-org-short-name` — and **all three are passed through untouched**, because organisation context is validated and never substituted.

> ⛔ **A service that scopes on `x-org-identifier` or `x-org-short-name` is adopting a check that does not protect it.** The membership verdict would be computed for the organisation named in `x-org-id` while the service reads a different header, and a caller can send their own `x-org-id` beside another organisation's short name. **If your service reads either, say so before adopting and do not assume this check covers you.**

*This is first on the list because it is the one failure a green adoption would hide.*

### 2. Does this service have a local user row to resolve?

**No local user table** → omit `resolveLocalIdentity` entirely. Omitting it is a *distinct state*, not a weaker one.

**It does** → supply the resolver, and expect **refusals where the donor proceeded**. A principal that verifies but resolves to no local row is refused here; `service_nearyest` currently continues with an id of `0` and lets a downstream check catch it. Requests that used to succeed will start returning 401.

### 3. Is any route in this service organisation-scoped?

**If none is,** `requireOrgMembership` is not mounted anywhere and the predicate is never reached. **Say that explicitly in the adopting PR and in a comment beside the predicate.** A reader who finds an `isMemberOf` that always returns `false` should not have to infer why — and it should be `false` rather than `true`, so that a route which later mounts the check fails loudly instead of silently passing.

**If any route is,** mount `requireOrgMembership` after `requireAuth` on that route and supply a predicate that answers *is this principal a member of this organisation* — never *may they do this*. **Today no service can supply a real one** — see below — so if you believe a route of yours needs it, that is a finding to report rather than a predicate to write.

### 4. What does this service do today on the four failure states, and which of them change?

| State | This package | What to check in your service |
|---|---|---|
| credential refused | `401` | were you already returning 401, or 500? |
| **auth service unreachable / 5xx / timeout** | **`503`** | anything treating this as "bad token" will stop doing so — including clients that retry a token refresh |
| principal verified, **no local row** | **`401`, never a placeholder identity** | **the behaviour change most likely to surprise you** |
| organisation not named on an org-scoped route | `403` | omitting the header is not a bypass |

**Adoption changes behaviour. That is the point of it, and it is not a regression — but the people running the service need to have been told which requests start failing and why.**

### A worked example

`service_orbit_kafka`, the first adopter: **(1)** scopes on nothing — `getConnection` accepts an organisation id and ignores it; **(2)** no local user table, resolver omitted; **(3)** no organisation-scoped route, so `requireOrgMembership` is unmounted and `isMemberOf` is `() => false`; **(4)** it had **no verification at all**, so both routes go from open to gated.

> ⚠️ Note what that example does **not** demonstrate. Kafka exercises **neither** the organisation seam nor the local-identity seam. It proves distribution and `requireAuth`. **It does not prove the package**, and a green first adoption should not be read as broader assurance than that.

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

**Organisation — validated, never substituted.** The caller keeps sending organisation context exactly as it does today; the package reads it, applies the membership predicate the service injected, and **passes every organisation header through byte-identical**. It never sets, clears or derives organisation context.

**Why it cannot be otherwise:** the access token carries `{ userId }` and nothing else — verified by reading the signing call in `service_auth` (`jwt.util.ts`, `const payload: TokenPayload = { userId }`), not a document about it. **There is no organisation in the token to re-establish anything from.** A package that "sets" organisation context would set it to empty on every request and fail every organisation-scoped screen in the live Flutter app.

### The three organisation headers

The live client sends **three**, on both mobile and web: `x-org-id`, `x-org-identifier`, `x-org-short-name`.

**Only `x-org-id` is validated**, because that is the one services actually scope on (`service_orbit_orgs` parses it as a positive integer and puts it in the SQL predicate; nothing reads `x-org-identifier`). **All three are passed through untouched.**

> ⚠️ **Known limitation.** A service that scopes on `x-org-short-name` or `x-org-identifier` **instead of** `x-org-id` is not protected by this package: a caller could send their own `x-org-id` alongside another organisation's short name. Validating those too needs a resolver that maps them to an organisation, which is authorisation-shaped and is not in this package. **If your service scopes on anything other than `x-org-id`, say so before adopting.**

---

## Fastify

```ts
import { createAuthClient, createFastifyAuth } from '@purpusgit/service-auth-client';

const client = createAuthClient({ authServiceBaseUrl, isMemberOf: () => false });
const auth = createFastifyAuth(client);

app.get('/things', { preHandler: [auth.requireAuth] }, handler);
```

**It is an adapter, not a second implementation.** The classification, both caches, the single-flight de-duplication and the resolver contract all live behind `client.verify()`, which the Express handler is also a thin adapter over. **This file contains no cache, no map, no timer and no HTTP call** — if it ever grows one it has stopped being an adapter.

**Three things differ between the frameworks, not one:**

| | Express | Fastify |
|---|---|---|
| mounting | positional: `router.get(path, mw, handler)` | route option: `{ preHandler: [mw] }` |
| continuing | **call `next()`** | **return without replying** |
| refusing | `res.status(n).json(b)` | `reply.status(n).send(b)` |

Nothing about the request or reply *shapes* forces more: both expose `headers.authorization` as a string and both are decorated by assignment.

> ⛔ **`@fastify/express` was considered and rejected.** It runs Express middleware unchanged and would have made this file unnecessary — but it hands middleware the **raw Node request**, so `req.principal = …` lands on an object a Fastify handler never reads. The gate would appear to run, report success, and decorate nothing. **That is the failure class this package exists to remove**, so it was not worth saving a file.

**No dependency on fastify.** The adapter's types are structural; a service that never imports it never pays for it.

---

## Membership is not implemented, anywhere, and that is a ruling rather than a gap awaiting work

**Every service that adopts this package passes `isMemberOf: () => false`.** kafka does. `service_marketplace_ecom` does. If you are adopting, you will too, and **that is the correct end state, not a stopgap you are expected to come back and finish.**

**Why, per the ruling on purpusgit/lanes#16:** the membership table carries **no link to a person** — no column and no foreign key. The only available path is a soft match on contact fields with no referential integrity, and the same-named UUID column that appears on both tables and looks like the obvious join **matches zero rows out of 32,959**. *(Those figures are from the ruling's database read, not from a measurement of my own.)* **Nobody builds the soft match.**

**So what does the seam buy, if nothing implements it?** Three things, and they are the reason it stays mandatory at construction rather than becoming optional:

1. **It refuses to let a service pretend.** There is no default and it never falls back to `true`, so a service cannot acquire an *apparent* membership check by omission.
2. **`() => false` fails closed and loudly.** If a route ever mounts `requireOrgMembership`, it answers 403 immediately rather than silently passing — the failure is visible in a minute, not discovered in an audit.
3. **When the schema gap closes, membership is one function against one join, in one place, for the whole estate** — which is the entire reason it was built as a seam instead of thirteen implementations.

> ⛔ **Do not read `isMemberOf` in a service's source and conclude that organisation membership is enforced there.** It is not enforced anywhere. **Organisation scoping in this estate works exactly as it did before this package existed**, and adopting the package does not change it.

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

## Resolving the caller: what the resolver is given, and what it is deliberately not

`resolveLocalIdentity(principal, context)` receives the verified principal and **one** other thing:

```ts
resolveLocalIdentity: async (principal, { bearerToken }) => {
  // a local table lookup needs neither of these beyond principal.userId;
  // an upstream call made AS THE CALLER needs the token, and nothing else.
  const r = await fetch(`${AUTH}/user/get/${principal.userId}`, {
    headers: { Authorization: `Bearer ${bearerToken}` },
  });
  return r.ok ? (await r.json()).data : null;   // null => the request is REFUSED
}
```

**Why this shape.** Two real services have now adopted this package and neither resolved the way the original seam assumed. The donor looked a caller up in its own database; `service_marketplace_ecom` has **no user table at all** and resolves by calling the auth service **as the caller**, which a `(principal) => …` signature cannot express. Resolution therefore had to move outside the package in that service — which meant **rebuilding the package's own caching there**, because a result resolved outside is a result cached outside, and an uncached per-request call to the auth service is the load hazard the negative cache exists to prevent.

**What was rejected, and why.** The obvious fix is to pass the resolver the **request**. It was rejected: the request carries the `x-user-*` headers this package has just overwritten, the organisation headers it validates but does not own, and a body and query a resolver has no business reading. Handing it back re-exposes exactly what the package spent effort normalising, and invites a resolver to make authorisation decisions — which it must never do.

**So the boundary is: everything upstream resolution needs, and nothing it does not.** That is one field. When something else turns out to be genuinely required, adding it here is a deliberate act with a reason attached — which passing the whole request would have skipped. **A conformance test asserts the context has exactly one key**, so widening it is a decision someone has to make on purpose rather than a drift.

> ⚠️ **`bearerToken` is a live credential.** It is the caller's, it is valid, and the package is handing it to service-supplied code. Use it to authenticate the one upstream call that resolves this principal. **Do not log it, do not store it, and do not use it to act on the caller's behalf beyond resolution.** The package already holds this token — it introspects with it — so nothing new is exposed *to the package*; what is new is that adopter code now receives it.

**Adding the second argument is not a breaking change.** A resolver written as `(principal) => …` keeps working unchanged, and a conformance test holds that.

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
