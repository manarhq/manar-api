# Kubernetes: chart layout, dependency graph, and CI security scanning

Phase 12b (Section 82: Kubernetes from day one; Section 83: container
hardening audit; Sections 77-78: CI security scanning). **This document
describes deployable-later artifacts. Nothing in this phase deploys
anything anywhere** — no cluster interaction beyond local, offline
validation (`helm template`, `kubeconform`, `kube-linter`), no
`manar.vax.sh` configuration. A separate, later, explicitly-requested
deployment phase covers actually rolling any of this out.

This document covers `manar-api`'s three charts (this repo). `manar-web`
and `manar-ai` each carry their own `docs/kubernetes.md` for their own
chart — see those repos.

## Chart layout

Three charts under `deploy/helm/`, one per deployable process this repo
produces:

| Chart                          | Deployable                                                                                            | Service?                       | Real health endpoint                                                                                                         |
| ------------------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `deploy/helm/manar-api`        | `dist/main.js` (`runtime` Dockerfile stage) — human REST API + agent mTLS listener                    | Yes, two ports                 | `GET /health/live`, `GET /health/ready` (`src/health/health.controller.ts`)                                                  |
| `deploy/helm/manar-api-worker` | `dist/worker.main.js` (`worker` Dockerfile stage — same image, different `CMD`) — the Temporal worker | No — no inbound traffic at all | none (no HTTP server in this process — see Dockerfile's `worker` stage comment); liveness is a `ps`-based exec probe instead |
| `deploy/helm/demo-soc-tools`   | `packages/demo-soc-tools/dist/main.js`                                                                | Yes                            | `GET /health/live`, `GET /health/ready` (`packages/demo-soc-tools/src/routes/health.ts`)                                     |

Each follows the same structure (standard `helm create` scaffold, trimmed
to what this phase actually needs — no `ingress.yaml`/`httproute.yaml`/
`hpa.yaml`, none of which are in scope here):

```
<chart>/
  Chart.yaml
  values.yaml
  templates/
    _helpers.tpl
    deployment.yaml
    service.yaml           # omitted for manar-api-worker (no Service)
    configmap.yaml
    secret.yaml
    networkpolicy.yaml
    serviceaccount.yaml
    NOTES.txt
    tests/test-connection.yaml   # omitted for manar-api-worker
```

Validated with:

```sh
helm lint deploy/helm/<chart>
helm template <chart> deploy/helm/<chart> --set image.tag=<tag> [...]
# then, against the rendered output:
kubeconform -strict -summary rendered/*.yaml
kube-linter lint rendered/
```

All three charts render 21 total resources, all schema-valid
(`kubeconform -strict`) and clean under `kube-linter`'s default check set
(non-root, read-only root filesystem, dropped capabilities, resource
requests/limits, pod anti-affinity, no `:latest` images — everything
kube-linter's default profile checks for).

## The two-listener manar-api process

`src/main.ts` opens **two** listeners in the same process:

- `PORT` (default 3000) — the human-facing REST API, plain HTTP.
- `AGENT_MTLS_PORT` (default 3443) — the agent-facing mutual-TLS HTTPS
  listener (`/agent/v1/*`, `src/agent-mtls/`), added in Phase 4 (Agent
  Identity & Enrollment). Client-certificate authentication is this
  listener's real trust boundary (Node's TLS layer rejects a handshake
  that doesn't chain to `AGENT_MTLS_CLIENT_CA_PATH`'s trust anchor before
  `AgentMtlsGuard` — defense in depth beyond that — ever runs). See
  `docs/agent-identity.md`.

**Container-hardening audit finding (fixed this phase):** the root
Dockerfile's `EXPOSE` only ever listed `3000` — this repo has had a
second, real listener on `3443` since Phase 4, and the Dockerfile had
drifted. `EXPOSE 3000 3443` now reflects both (this is a documentation-
only fix — `EXPOSE` doesn't gate anything at runtime — but the chart's
`Service`/container ports and `NetworkPolicy` below were designed against
the _real_ two-listener process either way).

Because of this, `deploy/helm/manar-api`'s `Service` exposes both ports,
and its `NetworkPolicy` treats them differently: `httpPort` ingress is
restricted to `manar-web` + the ingress-controller namespace; `agentMtlsPort`
ingress is deliberately _not_ source-restricted (mTLS, not network
policy, is the real boundary there — see values.yaml's `service`
comments).

## Container hardening audit: findings and fixes

Every Dockerfile in this repo (`Dockerfile` — both the `runtime` and
`worker` stages share it — and `packages/demo-soc-tools/Dockerfile`) was
re-audited against its _current_ real endpoints/routes/base images (not
a rubber stamp):

1. **`EXPOSE` drift (fixed):** see above — `3443` was missing.
2. **A pre-existing, out-of-this-phase's-scope build bug (worked around
   in the Dockerfile only):** the root `package.json`'s own `build`
   script (`nest build && pnpm --filter @manar/sdk-node build && pnpm
--filter @manar-ai/grpc-client build`) runs `nest build` _before_
   `@manar-ai/grpc-client`, but `src/ai-advisory/ai-advisory-client.service.ts`
   imports that package's compiled `dist/` output — so a clean install
   (no stale `dist/` from a previous local build to mask it) fails
   `nest build`'s typecheck. Reproduces on a bare `pnpm build`, not a
   Docker-specific issue, and is present on `main` already — not
   introduced by this phase. Fixing `package.json`'s script ordering is
   application-source territory, out of this phase's scope (Phase 12a
   owns `src/`/`package.json`). The Dockerfile's `build` stage instead
   pre-builds `@manar-ai/grpc-client` before invoking `pnpm build`, which
   makes the image buildable without touching that file. Report this to
   whichever workstream owns `package.json` next — the one-line real fix
   is reordering that script's three `&&`-joined commands.
3. **HEALTHCHECK routes — confirmed current, no drift:**
   `manar-api`'s `/health/live` (`src/health/health.controller.ts`),
   `demo-soc-tools`'s `/health/live` (`packages/demo-soc-tools/src/routes/health.ts`)
   are both real, unchanged since Phase 1/7a. The `worker` stage
   correctly has no `HEALTHCHECK` (no HTTP server in that process — see
   that stage's own doc comment in the Dockerfile).
4. **No build toolchain/dev deps leak into final images (confirmed):**
   spot-checked all three built images (`docker run ... which tsc pnpm`
   → not found in any of them; `ls node_modules | grep -E
'typescript|@types|eslint|prettier|jest'` → empty). `npm` itself is
   present only because it ships with the `node:24-alpine` base image —
   not a toolchain leak, no dev dependencies are installed (`prod-deps`
   stage uses `pnpm install --prod`).
5. **Base image tags — confirmed current-but-pinned, not `latest`, not
   stale:** `node:24-alpine` (Node 24, current LTS), all three
   Dockerfiles. No `:latest` anywhere in any of this repo's Dockerfiles.
6. **`.dockerignore` coverage — confirmed:** both the root and
   `packages/demo-soc-tools/.dockerignore` exclude `.env`/`.env.*`
   (with an explicit `!.env.example` allow-exception), `.git`, `node_modules`,
   `dist`, test files, and docs. No secret material is ever in a build
   context that reaches `COPY .`.

## Dependency graph → NetworkPolicy

The real dependency graph, from `deploy/docker-compose.yml` (this repo's
local-dev equivalent — same services, addressed by Docker Compose service
name there vs. Kubernetes Service name here) and from actually reading
each process's own NestJS module graph (not guessed):

| Caller                 | Real callees (confirmed via module imports)                                                                                                                                                                                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `manar-api` (HTTP app) | Postgres, Keycloak, OpenBao, OpenFGA, Temporal, Kafka, Redis, OpenSearch, `manar-ai`, `demo-soc-tools`                                                                                                                                                                                             |
| `manar-api-worker`     | Postgres, OpenBao, Temporal, Kafka, OpenSearch, `manar-ai`, `demo-soc-tools` — **not** Keycloak, **not** OpenFGA, **not** Redis (`WorkerAppModule` never imports `KeycloakModule`/`AuthorizationModule`/the Redis-backed live-SSE module — confirmed by reading its `imports:` array, not assumed) |
| `demo-soc-tools`       | nothing — a standalone, dependency-free deterministic test double                                                                                                                                                                                                                                  |

`manar-api-worker` is a subtlety worth calling out: `src/config/env.validation.ts`'s
`AppConfigSchema` is **one merged zod schema** shared by both processes
(`validate()` runs the same way for `src/main.ts` and
`src/worker.main.ts`), so the worker's `ConfigMap`/`Secret` still need
every _required_ (non-`.default()`) field from the whole schema —
including `KEYCLOAK_ADMIN_PASSWORD`/`OPENFGA_STORE_ID`-shaped values it
never actually dials over the network — or the process crash-loops on
startup. `deploy/helm/manar-api-worker/values.yaml` documents this
explicitly. **`NetworkPolicy` egress, unlike `ConfigMap`/`Secret` data, is
scoped to what's actually called**, not the full config surface — that
distinction is deliberate and is the whole point of doing this via a real
module-graph read instead of copy-pasting the HTTP app's policy.

`manar-web` needs egress only to `manar-api` and Keycloak — see that
repo's own chart/`docs/kubernetes.md`. It never talks to Postgres,
OpenFGA, OpenBao, Temporal, Kafka, Redis, OpenSearch, `manar-ai`, or
`demo-soc-tools` directly, and its `NetworkPolicy` doesn't grant it
egress to any of them.

Every `NetworkPolicy` in this repo is default-deny-by-omission
(`policyTypes: [Ingress, Egress]` with only the listed rules allowed) —
nothing gets unrestricted egress, and DNS (CoreDNS/kube-dns) is always
listed as its own explicit rule rather than assumed.

Assumption baked into every chart (documented, not hidden): dependency
pods are matched by `app.kubernetes.io/name` **within the policy's own
namespace** — i.e., a single `manar` namespace holding manar-api's three
Deployments plus Postgres/Keycloak/OpenBao/OpenFGA/Temporal/Kafka/Redis/
OpenSearch/`manar-ai`/`demo-soc-tools`, matching the single-Docker-network
posture `deploy/docker-compose.yml` already has locally. A real
deployment that splits dependencies across namespaces needs a
`namespaceSelector` added per egress rule — not done here since it isn't
this repo's call to make about a cluster topology that doesn't exist yet.

## Secrets

No chart embeds a real secret value. `values.yaml`'s `secrets.data`/
`agentMtls.certs.*` fields are empty-string placeholders; `secrets.create`
(default `true`) only controls whether _this chart_ renders a `Secret`
object from those placeholders — set it to `false` and pre-create a
`Secret` of the same name via an external secret manager (OpenBao →
Kubernetes sync, External Secrets Operator, Sealed Secrets) instead, with
no template change needed. `deploy/helm/manar-api`'s agent-mTLS
cert/key/CA material is mounted as a read-only Secret volume at
`/app/deploy/openbao/` (matching `AGENT_MTLS_SERVER_CERT_PATH`'s default),
never baked into the image.

## Security posture (every chart)

- `runAsNonRoot: true`, fixed non-root UID/GID matching each Dockerfile's
  own `USER` (`manar`/`demosoc`, both `1001:1001`).
- `readOnlyRootFilesystem: true` — the only writable path is an `emptyDir`
  mounted at `/tmp`; agent-mTLS cert material is a separate read-only
  Secret mount.
- `allowPrivilegeEscalation: false`, `capabilities: drop: [ALL]`,
  `seccompProfile: RuntimeDefault`.
- Resource requests/limits set on every container (no chart ships an
  unbounded container).
- `serviceAccount.automount: false` — none of these processes call the
  Kubernetes API.
- Default soft pod anti-affinity (`preferredDuringSchedulingIgnoredDuringExecution`,
  `topologyKey: kubernetes.io/hostname`) on the two 2-replica Deployments.

## CI security scanning (`.gitlab-ci.yml`)

Appended a new `security` stage (after the existing `lint`/`typecheck`/
`test`/`build` stages — none renamed, reordered, or removed). One tool
per problem (no redundant pair solving the same problem twice):

| Tool        | Version (pinned image)                    | Problem                                                                                                                                                        | Threshold                                                                                                                        |
| ----------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Trivy       | `aquasec/trivy:0.71.0`                    | Dependency scan (`trivy fs`) **and** container image scan (`trivy image`, all three built images)                                                              | Fail on **HIGH/CRITICAL** only (`--ignore-unfixed`); full JSON report always uploaded regardless of outcome                      |
| Gitleaks    | `ghcr.io/gitleaks/gitleaks:v8.30.1`       | Secret scanning, full git history every run (`--log-opts="--all"`), not just the diff                                                                          | Fail on **any** finding not already in `.gitleaks.toml`'s allowlist — no acceptable severity tier for a leaked credential        |
| Semgrep     | `semgrep/semgrep:1.172.0`                 | SAST                                                                                                                                                           | Fail on **ERROR** severity only (`--config auto`'s highest tier); WARNING/INFO still reported in the JSON artifact, non-blocking |
| Syft        | `anchore/syft:v1.51.0`                    | SBOM generation (CycloneDX), all three built images                                                                                                            | Artifact-only job — never fails the pipeline                                                                                     |
| kubeconform | `ghcr.io/yannh/kubeconform:v0.8.0-alpine` | Kubernetes manifest **schema** validity                                                                                                                        | Fail on **any** `-strict` violation                                                                                              |
| kube-linter | `stackrox/kube-linter:v0.8.3`             | Kubernetes manifest **best-practice/security lint** (non-root, resource limits, anti-affinity, `:latest`, ...) — complements kubeconform, doesn't duplicate it | Fail on any default-profile finding                                                                                              |

`docker:build-images` (in the existing `build` stage, so its artifacts —
three `docker save` tarballs — exist before any `security`-stage job that
`needs:` them) builds all three images with the same `--target`/`-f`
invocations documented above.

**Verified locally before wiring into CI** (all commands above run
directly against this repo, not assumed to work):

- All three images build successfully (`docker build --target runtime`,
  `--target worker`, `-f packages/demo-soc-tools/Dockerfile`).
- Trivy image scan found real HIGH/CRITICAL CVEs in transitive npm
  dependencies shared across all three images (`brace-expansion`, `tar`,
  `undici`, `deepmerge-ts`, `ip-address`) — the gate would correctly fail
  the pipeline as designed. **Fixing these dependency versions is a
  `pnpm-lock.yaml` change — application/dependency-management territory,
  out of this phase's Dockerfile/Helm/CI scope** — flagged here for
  whichever workstream owns dependency upgrades next.
- Trivy filesystem scan found one real HIGH CVE (`deepmerge-ts`,
  CVE-2026-40345) directly in `pnpm-lock.yaml` — same note as above.
- Semgrep: 0 findings at ERROR severity across 345 scanned files.
- Syft: 1678 cataloged components in the `manar-api` image's SBOM.
- kubeconform: 21/21 resources valid (`-strict`).
- kube-linter: 0 findings against the default check profile.

### Gitleaks: one-time full-history scan (run now, not deferred)

Ran `gitleaks git --log-opts="--all"` against this repo's full history
(101 commits) as this phase requires, not just wired for future commits.
**One finding, triaged as a confirmed false positive, not a real secret:**
`README.md`'s CircleCI badge URL —
`https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456` —
is NestJS's own default `nest new` scaffold boilerplate, pointing at the
_upstream_ `nestjs/nest` GitHub repo with its own well-known sample
placeholder token, never edited since Phase 1, never a value issued to or
usable against this repo. Documented and allowlisted by exact match
(not by deleting/rewriting published history for a non-issue) in
`.gitleaks.toml`; re-running the same scan with that config applied
confirms `no leaks found`. No other findings.

## Later: actually deploying this (out of scope now)

Not done in this phase. When a real deployment phase happens: pick a
target namespace (`manar` per the assumption above, or update every
chart's `NetworkPolicy` `namespaceSelector`s if not), populate every
`Secret` via whatever secret manager the target cluster uses (never a
committed values file), point `image.repository`/`image.tag` at real
CI-built, Trivy-scanned images, and run `helm install`/`helm upgrade`
against a real cluster — none of which this phase does.
