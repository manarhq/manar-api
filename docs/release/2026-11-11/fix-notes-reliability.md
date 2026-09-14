# Fix notes — reliability and deployability

Release `2026-11-11`, branch `release/2026-11-11` (`manar-api`). Five
confirmed defects, fixed together because they share one theme: the
process behaved correctly right up until something around it moved —
a dependency went away, a pod was rescheduled, a tenant got large, or the
chart was installed on a cluster for the first time.

Nothing here is committed or pushed. Verification was `npx tsc --noEmit`,
`npx vitest run`, and `helm template` against both charts; the e2e suites
need real Postgres, Keycloak, Redis, Kafka and OpenSearch and were not
run.

**Read §1's "The fail-open decision" first if you are reviewing only one
thing.** It is the only change here that trades away enforcement, and it
wants an explicit sign-off.

---

## 1. A Redis outage restarted every pod, via the liveness probe

**Was** — `TenantThrottlerGuard` is registered as a global `APP_GUARD`
(`src/rate-limit/rate-limit.module.ts:42`), so it ran on every route in
the application, `/health/live` included. It carried no `shouldSkip`
override and there is no `@SkipThrottle` anywhere in the codebase
(`src/rate-limit/tenant-throttler.guard.ts:25-43`, pre-fix).

`@nestjs/throttler` 6.5.0's `ThrottlerGuard.handleRequest` calls
`this.storageService.increment(...)` with no error handling of its own
(`node_modules/@nestjs/throttler/dist/throttler.guard.js`), and
`RedisThrottlerStorageService.getClient` throws when Redis is unreachable
(`src/rate-limit/redis-throttler-storage.service.ts:190`).

So: Redis goes away → `/health/live` returns 500 → the kubelet reads that
as a dead process → **every replica is restarted**, simultaneously,
because they all share the same Redis. A degraded-but-serving dependency
became a total outage plus a crash-loop.

**Now** — two overrides in
`src/rate-limit/tenant-throttler.guard.ts`:

- `shouldSkip(context)` returns `true` for any path under `/health/`,
  matched via `isHealthRoutePath` in the new leaf module
  `src/health/health.routes.ts` (no imports of its own, so nothing can
  cycle). Matching is anchored and strips the query string, so
  `/health/ready?verbose=1` is exempt while `/healthcheck-proxy` and
  `/tenants/health` are not.

  Matched by path rather than by `@SkipThrottle()` deliberately:
  `@SkipThrottle()` with no arguments only skips a throttler _named_
  `default`, and this application's only throttler is named `human`
  (`RateLimitModule`) — so the decorator would silently have skipped
  nothing, which is precisely the failure mode being fixed.

- `handleRequest(props)` wraps `super.handleRequest` and fails open on a
  storage error. See below.

`HealthController` now takes its `@Controller()` prefix from the same
constant, so the exemption and the routes cannot drift apart.

### The fail-open decision — please review this explicitly

**A rate-limit storage failure now allows the request through, logged at
`error`, instead of returning 500.**

The reasoning, in order of importance:

1. **Rate limiting here is availability protection, not an authorization
   control.** Its documented purpose (that guard's own class comment) is
   that one tenant's burst must not starve another's. It decides nothing
   about _who may do what_. Every actual authorization control —
   `JwtAuthGuard`, `RolesGuard`, `AgentMtlsGuard`, `BffServiceGuard`,
   `PolicyEngine`, OpenFGA — runs **after** this guard and is entirely
   untouched by the catch. A Redis outage therefore cannot become an
   authorization bypass; it can only become a temporarily unenforced
   quota.
2. **Failing closed is strictly worse than the risk it guards against.**
   It would mean a Redis outage returns 500 for 100% of authenticated
   traffic on every replica — the component whose entire job is keeping
   the API available under load would become the thing that takes the API
   down.
3. **The window is bounded and loud.** Every occurrence logs at `error`
   from `TenantThrottlerGuard`, and `RedisThrottlerStorageService` logs
   its own connection errors. The operator's real "stop this tenant now"
   control, the kill-switch surface (`src/kill-switches/`), is backed by
   Postgres rather than Redis and keeps working throughout.

Scope of the catch is deliberately narrow: an `HttpException` — which is
what `ThrottlerGuard.throwThrottlingException` raises for a genuine
over-limit 429 — is **re-thrown untouched**. Enforcement is completely
unchanged whenever Redis is healthy. Only infrastructure failures fail
open.

**What would change this decision:** if rate limiting is ever used as a
brute-force or credential-stuffing control on an unauthenticated route,
fail-open stops being correct for _that_ route and it needs its own
fail-closed throttler. Nothing in the codebase does that today.

**Pinned by** — `src/rate-limit/tenant-throttler.guard.spec.ts`:
`/health/live` answers with the storage throwing and `increment` never
called; look-alike paths still get limited; a storage failure on `/tasks`
allows the request; a `BLOCKED` storage record still raises
`ThrottlerException`.

---

## 2. `/health/ready` was a static stub wired as the readiness probe

**Was** — `src/health/health.controller.ts:26-30` returned
`{ status: 'ok' }` unconditionally, under a Phase-1 comment saying there
were no downstream dependencies to check yet. There are now nine, and
`deploy/helm/manar-api/values.yaml:102-109` had that handler wired as the
Kubernetes `readinessProbe`. A replica whose control database had gone
away stayed in the Service's endpoint list and kept accepting requests it
could only 500.

`TenantDatabaseManager.checkHealth`
(`src/database/tenant-database-manager.service.ts:274-282`) had carried a
"exposed for a future `/health/ready` aggregation" comment since Phase 2.

**Now** — three new files under `src/health/`:

- `readiness.ts` — the pure engine. Per-dependency status is `ok` /
  `degraded` / `stale` / `unhealthy`; `stale` specifically means "the
  probe blew its budget, so the state is unknown", kept distinct from
  "the probe came back negative" because those are different facts during
  an incident. `runProbe` applies a **hard 2s timeout** per probe and
  absorbs the abandoned attempt's late rejection so it can never surface
  as an unhandled rejection. `evaluateReadiness` runs all probes
  concurrently, so the endpoint's worst case is one budget rather than
  nine.
- `tcp-reachability.ts` — address parsing plus a connect-only reachability
  check.
- `readiness.service.ts` — assembles ten probes across the nine
  dependencies in the chart's own `networkPolicy.egressTargets`.

`GET /health/ready` returns the full per-dependency body either way: 200
when ready (including `degraded`), 503 (`ServiceUnavailableException`
carrying the same report object) when a required dependency is not `ok`.
`/health/live` is unchanged and stays a constant — its failure mode is
"restart the container", so it must depend on nothing outside the
process.

### Which dependencies are required, and why almost none are

An unready pod is removed from its Service's endpoints, and every replica
of this Deployment shares every dependency. Marking a dependency
`required` therefore converts _its_ outage into a **total** outage. Only
two clear that bar, and both sit on every authenticated request path:

| Probe              | Required           | Check                                                            | Why                                                                                                                           |
| ------------------ | ------------------ | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `postgres-control` | **yes**            | `SELECT 1` via `ControlPrismaService`                            | Every request resolves its tenant through it.                                                                                 |
| `openfga`          | **yes**            | TCP                                                              | `OpenFgaClientService.check` throws on transport failure rather than failing open, so every authorized route 500s without it. |
| `postgres-tenant`  | no                 | `TenantDatabaseManager.checkHealth` on one sampled ACTIVE tenant | One tenant's database being down must not evict the replica and break every other tenant.                                     |
| `openbao`          | no                 | TCP                                                              | Cached tenant clients keep working.                                                                                           |
| `keycloak`         | no                 | TCP                                                              | Lazy, request-time only; JWT verification uses cached JWKS.                                                                   |
| `temporal`         | no                 | TCP                                                              | Workflows stall; synchronous routes are unaffected.                                                                           |
| `kafka`            | no                 | TCP                                                              | `KafkaPublisherService` never throws to its caller; the Postgres audit row is authoritative.                                  |
| `opensearch`       | no                 | TCP                                                              | Indexing catches up on its own.                                                                                               |
| `redis`            | no                 | TCP                                                              | Rate limiting fails open (§1); idempotency and SSE degrade.                                                                   |
| `ai-advisory`      | **no, by mandate** | TCP                                                              | Section 80 — an AI outage must never change a deterministic outcome.                                                          |

**The AI constraint is enforced structurally, not by convention**: only a
`required` probe can set `ready: false`, and `ai-advisory` is not one.
An advisory outage produces `status: 'degraded'`, `ready: true`, and a
full explanation in the body. There is no path by which it becomes a
perpetual readiness failure for a valid deterministic profile.

### Why TCP probes for the optional dependencies

None of `KafkaPublisherService`, `RedisThrottlerStorageService`,
`IdempotencyStoreService`, `RedisPubSubService`, `TemporalClientService`,
`KeycloakAdminClient` or `AiAdvisoryClient` exposes a side-effect-free
ping — every public method does real work (publishes an event, increments
a counter, fetches an admin token, spends a model call). On a 10-second
kubelet cadence that would make the health check itself load on the
dependency it is checking, and for the AI service it would mean paying for
inference to ask whether inference is available.

A TCP connect is honestly coarse: it proves the network path and the
listener, not correct behaviour behind it. That is the right resolution
where the only consequence is a `degraded` flag in the body — and the one
dependency where readiness genuinely gates traffic (`postgres-control`)
gets a real query instead. Adding purpose-built `ping()` methods to those
service classes is the obvious follow-up; it was out of scope here
because those files belong to other work in this release.

**Pinned by** — `src/health/readiness.spec.ts` (optional-AI down stays
ready and degraded; optional-AI _hanging_ stays ready; a required
dependency down does not ready; a required dependency's probe timing out
does not ready; a hanging probe returns `stale` instead of hanging;
probes run concurrently; a late rejection from an abandoned probe does not
escape) and `src/health/readiness.service.spec.ts` (the required set is
exactly `openfga` + `postgres-control`; `ai-advisory` is never required; a
sampled tenant DB failing still readies). `src/health/health.controller.spec.ts`
covers the 200/503 mapping and that liveness never touches a dependency.

---

## 3. No graceful shutdown anywhere

**Was** — `enableShutdownHooks()` appeared nowhere in `src/`, and neither
Helm deployment template set `preStop` or
`terminationGracePeriodSeconds`. SIGTERM therefore killed the process
outright on every rollout, scale-down, node drain and eviction, so
`onModuleDestroy` never ran in production:

- `TenantDatabaseManager.onModuleDestroy` never disconnected its cached
  per-tenant Prisma clients (up to `TENANT_DB_CLIENT_CACHE_MAX`, each a
  real Postgres pool). Postgres held those backends until its own
  keepalive reaped them — leaking server-side connections against
  `max_connections` exactly as the replacement replicas were opening
  theirs.
- `KafkaPublisherService`'s producer never flushed or disconnected.
- `ControlPrismaService` and the three Redis clients were never closed.
- Fastify never stopped accepting connections before the process died, so
  every in-flight request became a client-visible 502.

**Now** —

- `src/main.ts`: `enableGracefulShutdown(app)` before each `listen()`,
  for **both** Nest applications (the human HTTP app and the agent mTLS
  app have separate DI containers and therefore separate Prisma/Kafka/
  Redis instances). Registered before `listen()` so a SIGTERM during a
  slow startup is handled rather than racing the listener. Nest re-raises
  the signal to itself after its own cleanup; because the other app's
  listener is still installed at that moment, the re-raise is absorbed and
  the process only terminates once the second app has closed too.
- `src/worker.main.ts`: signal handlers now installed the instant the DI
  container exists, before the (slow) Temporal connect — a SIGTERM during
  startup previously hit Node's default handler and killed the process
  with connections already open. After the workers are polling, a signal
  drains them (`Worker.shutdown()`), and the `finally` closes the Temporal
  connection and then the DI container, each via `closeQuietly` so one
  failing step cannot skip the next. `void bootstrap()` became
  `bootstrap().catch(...)` with a non-zero exit code.

  Deliberately **not** `enableShutdownHooks()` here: Nest's hook closes
  the container and re-raises the signal, which would race the Temporal
  drain and kill in-flight Activities mid-execution. Drain first, close
  after.

- `deploy/helm/manar-api/templates/deployment.yaml`: a `preStop` exec
  `sleep {{ .Values.preStopSleepSeconds }}` (default 10, set to 0 to
  disable) plus `terminationGracePeriodSeconds: 45`. The sleep covers the
  window in which the kubelet has sent SIGTERM but kube-proxy/the ingress
  have not finished removing this pod from their endpoint tables — that
  race is what makes rollouts drop requests, and no amount of in-process
  shutdown handling closes it. `sleep` is busybox's, already on PATH in
  the `node:24-alpine` runtime image, and needs no shell, so it works
  under `readOnlyRootFilesystem` with all capabilities dropped.
- `deploy/helm/manar-api-worker/templates/deployment.yaml`:
  `terminationGracePeriodSeconds: 120`, no preStop. There is no Service
  and nothing ever connects _to_ this pod, so there is no endpoint race to
  sleep through — but an in-flight Activity can legitimately run for a
  while, and a SIGKILL mid-Activity makes Temporal wait out that
  Activity's start-to-close timeout before any worker retries it.

**Not pinned by a unit test.** Signal handling and container lifecycle are
not meaningfully unit-testable here; the changes are `helm template`-
verified and reviewed by reading. An e2e "roll the Deployment and assert
zero 5xx" check would be the real proof and needs a cluster.

---

## 4. `GET /audit/verify` loaded the whole audit table into memory

**Was** — `src/audit/audit.service.ts:240-242`:

```ts
const events = await tenantClient.auditEvent.findMany({
  orderBy: { sequence: 'asc' },
});
```

No `take`, no cursor. Reachable over HTTP by any
`AUDITOR`/`SECURITY_ADMIN`/`TENANT_OWNER`
(`src/audit/audit.controller.ts:222-236`) against a 768Mi container limit.
One large tenant's verification request OOM-killed the replica handling
it, taking every other in-flight request on that pod with it.

**Now** — the same walk, keyset-paginated in 1000-row batches
(`AuditService.VERIFY_CHAIN_BATCH_SIZE`), streaming `expectedPreviousHash`
across batch boundaries. Peak memory is bounded by the batch, not the
chain.

Keyset (`WHERE sequence > ?`) rather than `skip`/`take` or Prisma's
`cursor`: offset pagination would re-scan and re-sort every verified row
per page and would silently _skip_ a row if retention pruned the head
mid-walk (for a chain verifier, that means reporting a break that isn't
one); Prisma's `cursor` wants a uniquely-identifying field, and
`AuditEvent.sequence` is a plain `Int @default(autoincrement())`, not
declared `@unique` in `prisma/tenant.prisma`. Append-only-ness is what
makes paging safe at all — rows are never updated or reordered, so a row's
`sequence` is fixed from insert onward.

One deliberate ordering change: `auditChainAnchor.findMany()` now runs
_before_ the first batch instead of after the whole-table read. Retention
only ever adds anchors, so reading them first can only make the walk
recognise a linkage it would otherwise reject — never the reverse.

**Response shape is unchanged.** Still
`{ valid: true } | { valid: false, brokenAt: string }`, matching
`VerifyAuditChainResponseDto`. `manar-web` needs no change. The
verification result is exactly as correct as before: the walk is
inherently sequential, so carrying the running hash across a page break is
equivalent to carrying it across two adjacent array elements.

`src/audit/audit.controller.ts` was **not** modified — the endpoint needed
no change once the service was bounded.

**Pinned by** — `src/audit/audit.service.spec.ts`, over a 2500-event chain
(2.5 batches) built with the real `computeEventHash`:

- **a tampered event at index 1500 — the second batch — is still detected,
  at the right event id.** This is the test that proves batching did not
  weaken the check.
- a deleted event across a batch boundary is detected at the row that lost
  its parent.
- tampering in the first batch is still detected.
- anchor-awareness still works for a retention-pruned head (and an
  unrecognised anchor is still rejected).
- the tail is still checked against `AuditChainState` after the last
  batch.
- more than one page was fetched and no page held the whole chain.

---

## 5. The shipped Helm charts could not boot

Two independent fatal misconfigurations, plus a Dockerfile defect.

### (a) `MANAR_BFF_SERVICE_TOKEN` was absent from every chart

`src/tenants/tenants.config.ts:32` declares it `z.string().min(16)` with
no default, and `validate()` runs identically for `src/main.ts` and
`src/worker.main.ts`. It appeared nowhere under `deploy/` — not in
`deploy/helm/manar-api/values.yaml:167-174` and not in the worker's. Both
Deployments crash-looped before opening a listener.

**Now** — added to `secrets.data` in both charts, following the existing
convention exactly: an **empty placeholder**, populated at install time or
supplied by an externally managed Secret with `secrets.create: false`. No
plaintext secret is introduced anywhere. Both entries carry a comment
explaining the `min(16)` constraint and that the worker needs it purely
because the schema is shared.

### (b) `NODE_ENV: production` with no `CORS_ALLOWED_ORIGINS`

`deploy/helm/manar-api/values.yaml:119` set `NODE_ENV: production` and
never set `CORS_ALLOWED_ORIGINS`, which defaults to `'*'`
(`src/security/security.config.ts:25`). `resolveCorsOrigin`
(`src/security/cors.ts:20-24`) _throws at bootstrap_ on a production
wildcard — Section 99's deliberate hard rule. So the omission did not
produce a permissive API; it produced a pod that never listened.

**Now** — `CORS_ALLOWED_ORIGINS: https://manar.example.com` in the
manar-api chart's `config`, with a comment explaining that this is a
placeholder in the same spirit as `image.repository` and must be
overridden per environment with the real manar-web origin(s).

Deliberately **not** added to the worker chart: it has a schema default so
it is not _required_, and `resolveCorsOrigin` is reached only from
`setupCors`, which `src/worker.main.ts` never calls (it constructs no
FastifyAdapter). Setting it there would be config nothing reads. That
asymmetry is documented in the worker chart's header.

> Note for whoever installs this: `https://manar.example.com` is a
> placeholder. Left as-is the API boots but rejects the real UI's origin.
> A wrong-origin-but-running pod is a much better failure than a
> crash-loop, and Section 99 forbids the alternative.

### (c) `Dockerfile:94` inherited the HTTP HEALTHCHECK

`FROM runtime AS worker` inherits its parent stage's `HEALTHCHECK`, so the
worker image silently kept the `runtime` stage's
`curl /health/live` check — against a port nothing in that container
listens on — despite the comment at `:91-93` claiming there was none.
Every worker container reported `unhealthy` forever, and any orchestrator
acting on Docker health status would restart-loop a working worker.

**Now** — `HEALTHCHECK NONE` on the `worker` stage, with the comment
corrected to explain that inheritance is why the line is needed.

---

## Verification

```
$ npx tsc --noEmit
(no output — clean)

$ npx vitest run
 Test Files  32 passed (32)
      Tests  296 passed (296)

$ helm template deploy/helm/manar-api      # renders
$ helm template deploy/helm/manar-api-worker  # renders
```

Rendered output spot-checked for `MANAR_BFF_SERVICE_TOKEN` (both charts),
`CORS_ALLOWED_ORIGINS`, `terminationGracePeriodSeconds` (45 / 120), and
the `preStop` `sleep 10` exec.

`pnpm lint` was **not** run — it is configured with `--fix` and rewrites
generated files.

## Known gaps

- Graceful shutdown has no automated test (see §3).
- Seven of the ten readiness probes are TCP-reachability rather than
  client-level health calls, because the relevant service classes expose
  no side-effect-free ping and those files are owned by other work in this
  release (see §2).
- `AuditEvent.sequence` has no index in `prisma/tenant.prisma`. Keyset
  pagination is correct without one, but each batch still costs a sort;
  adding `@@index([sequence])` would make the batched walk cheap as well
  as bounded. Not done here — `prisma/**` was out of scope.
