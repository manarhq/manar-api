# Fix notes — JWT audience/algorithm pinning, constant-time secret comparison, SSRF redirect bypass

Release `2026-11-11`, branch `release/2026-11-11` (`manar-api`). Three
confirmed security defects, fixed together because they share one theme:
a check that was performed, but not performed on the thing that actually
mattered.

Nothing here is committed or pushed. Only unit-level verification was run
(`npx tsc --noEmit`, `npx vitest run`); the e2e suites need real Postgres,
Keycloak, Redis, Kafka and OpenSearch and were not run.

## 1. JWT verification omitted audience and algorithm pinning

**Was** — `src/auth/jwt-auth.guard.ts:83-85`:

```ts
const { payload } = await jwtVerify(token, jwks, {
  issuer: knownIssuer.issuerUrl,
});
```

That is the entire trust decision. `KnownIssuerRegistry` had already
established that the issuer is a realm this deployment provisioned, and
`jwtVerify` established that the realm signed the token — but nothing
established what the realm signed it _for_. Every token a tenant's realm
mints carries the same `iss`, the same `sub`, and the same
`realm_access.roles` array, which `syncRoleBindings` then writes into
`RoleBinding` rows verbatim. So an ID token (a value `manar-web` holds in
the browser-facing half of the login flow), a refresh token, or an access
token issued to any _other_ client registered in that realm all
authenticated as the user, with the user's full role set.

`alg` was likewise unpinned: `jose` verified under whatever algorithm the
token's own header asked for, which is attacker-controlled input, against
key material published at a public JWKS endpoint.

**Now** — three additions to the same call plus one post-verification
check (`checkTokenIsAnAccessTokenForThisClient`):

- `algorithms: ['RS256', 'RS384', 'RS512']`. Realms are created by
  `KeycloakAdminClient.createRealm` with no `defaultSignatureAlgorithm`,
  so Keycloak 26 (`deploy/docker-compose.yml`) signs with `RS256` from the
  realm's auto-generated `rsa-generated` key provider. `ES*` is absent
  because no EC key provider is ever created; `RS384`/`RS512` are included
  so an operator _strengthening_ a realm's algorithm cannot lock every
  human out.
- `clockTolerance: 30` seconds, for ordinary NTP drift between the
  Keycloak host and this one.
- `typ` must be `Bearer` — Keycloak's own payload claim naming the token
  kind (`ID` for ID tokens, `Refresh`/`Offline` for refresh tokens). A
  token with no `typ` at all is rejected too.
- The token must have been issued to this deployment's own client
  (`KEYCLOAK_CLIENT_ID`, default `manar-api`).

### Why the audience check is `azp`-first

Checking `aud` alone would have been wrong for this deployment and would
have broken login on the first request.
`KeycloakAdminClient.createConfidentialClient` registers no audience
mapper, so a real access token from these realms has `aud: ["account"]`
and carries the requesting client in `azp` instead — Keycloak's standard
default-configuration shape. So `azp` is authoritative when present
(present _and_ different means the token belongs to another client, which
is a rejection), and `aud` is the fallback for the OIDC-standard case
where a token has a single audience and therefore omits `azp`. The e2e
fixture path (`test/support/keycloak-test-helpers.ts`'s direct-grant
tokens) produces exactly the `azp`-carrying shape and still passes.

**Pinned by** `src/auth/jwt-auth.guard.spec.ts` — a new unit spec that
fabricates realm-signed tokens with `jose` and drives the guard with
in-memory fakes. Seven of its ten cases fail against the pre-fix guard.

## 2. Non-constant-time comparison of two shared secrets

**Was** — `src/tenants/bff-service.guard.ts:44` and
`src/kill-switches/platform-operator.guard.ts:60`, both `provided !== expected`.
V8 compares strings byte-wise and returns at the first difference, so
both secrets were recoverable one byte at a time by an attacker able to
time enough requests. The first is the _only_ credential on
`GET /tenants/:slug/oidc-client-secret`; the second gates the
platform-wide kill switch.

**Now** — both call `constantTimeEqual`
(`src/common/security/constant-time-compare.ts`), which hashes each side
to a fixed 32-byte SHA-256 digest and compares the digests with
`node:crypto`'s `timingSafeEqual`. Hashing first is what lets this handle
unequal lengths without the `if (a.length !== b.length) return false`
guard every naive `timingSafeEqual` call site needs — that guard is itself
an early return, and for a shared token (unlike
`webhook-signing.ts`'s fixed-width hex digest) the length is genuinely
secret.

**Pinned by** `src/common/security/constant-time-compare.spec.ts`. The
timing property itself is a review-level guarantee of the implementation;
what the tests pin is that differing-length inputs return a correct answer
through the same code path rather than throwing or short-circuiting.

## 3. SSRF allow-list bypass via HTTP redirect, leaking tool credentials

**Was** — `src/tools/http-tool.adapter.ts:111` and
`src/webhooks/webhook-delivery.service.ts:126`, both bare `fetch` calls.
`assertSafeOutboundUrl` validated the URL the tenant registered, and then
undici's default `redirect: 'follow'` followed redirects _inside the
runtime_, with no callback and no application-level check on the target.
The string `redirect:` appeared nowhere in `src/`.

So a tenant-registered host that resolves to a perfectly public address
could answer `302 Location: http://169.254.169.254/latest/meta-data/` and
the process would fetch the cloud instance metadata service — and undici
replays request headers on a same-scheme redirect, so
`HttpToolAdapter`'s `Authorization: Bearer <broker-issued credential>`
went with it. One SSRF bypass and one credential-exfiltration primitive,
both reachable by anyone who can register a tool or a webhook endpoint.

**Now** — one shared `safeOutboundFetch` in
`src/common/ssrf/url-safety.ts` (deliberately alongside
`assertSafeOutboundUrl` rather than duplicated per caller, matching that
module's existing stance), used by both call sites:

- `redirect: 'manual'`, with an explicit hop loop.
- `assertSafeOutboundUrl` re-runs on **every** hop, not just the first.
- Any hop to a different origin (scheme, host, or port) drops
  `Authorization`, `Cookie` and `Proxy-Authorization`, so the worst a
  redirecting endpoint achieves is an _unauthenticated_ request elsewhere.
- The chain is capped at `MAX_OUTBOUND_REDIRECTS` (3); exceeding it raises
  `UnsafeOutboundUrlError`, the failure shape both callers already handle.
- Method/body rewriting follows the same rules the runtime applied (303 →
  bodiless `GET`; 301/302 on a `POST` → `GET`; 307/308 preserve), so a
  legitimate endpoint sees no behavioural change.
- Redirect-hop bodies are cancelled rather than left for the GC to
  release.

`Manar-Signature` is deliberately **not** stripped on a cross-origin hop:
it is an HMAC over one specific body and timestamp, not a bearer
credential, and a receiver that legitimately redirects still needs it.

Response size: `HttpToolAdapter` previously did an unbounded
`response.json()` on a tenant-controlled endpoint's answer. It now reads
through `readBoundedResponseText` (2 MiB ceiling, `Content-Length`
checked first and the stream counted regardless of what it claimed);
oversized responses fail as `response_too_large` without consuming the
retry budget. `WebhookDeliveryService` never reads a response body at all
— only the status — so it has no limit to impose, but it now releases the
body explicitly.

Timeout behaviour is unchanged in both callers: the same `AbortController`
and the same `REQUEST_TIMEOUT_MS`/`WEBHOOK_DELIVERY_TIMEOUT_MS` now cover
the whole redirect chain rather than a single request.

**Pinned by** `src/common/ssrf/url-safety.spec.ts` — sixteen new cases
covering a redirect to the metadata service by IP and by hostname, a
redirect to a non-`http(s)` scheme, `Authorization` dropped cross-origin
and on a scheme change but kept same-origin, method/body rewriting, the
hop cap, and the response-size ceiling. Six of them fail if the per-hop
validation or the header stripping is removed.

### Known limitation, unchanged

There is still a TOCTOU gap between `assertSafeOutboundUrl`'s DNS
resolution and the separate resolution `fetch` performs when it connects,
so a sufficiently fast DNS rebind can slip an address past the check.
Closing it properly requires a custom undici connector that pins the
validated address — a larger change than this fix. The redirect hole
closed here was the _practical_ bypass: it required nothing but an HTTP
response.

## Not fixed here

`src/tools/mcp-tool.adapter.ts` also makes outbound calls to a
tenant-registered `Tool.baseEndpoint`, through the MCP SDK's
`StreamableHTTPClientTransport` rather than through `fetch` directly. Its
redirect behaviour was not audited or changed in this pass (that file is
outside this fix's scope and was being edited concurrently).
