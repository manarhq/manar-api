# manar-api — control plane

Workspace context and the build program: `../CLAUDE.md`, `../MANAR-BUILD-SPEC.md` and
`../MANAR-BUILD-SPEC-ADDENDUM-01.md` (which wins where they differ). Read them first. This file
holds what is specific to this repo. The architecture decision this repo is being built toward is `docs/adr/ADR-0001-capability-based-enforcement.md`.

## Stack

NestJS 11 on Fastify 5, TypeScript, Prisma (two schemas), OpenFGA, Temporal, OpenBao, Redis,
Kafka, OpenSearch, Keycloak (human OIDC), `@peculiar/x509` (agent CA), `jose`, zod,
`@modelcontextprotocol/sdk` (client), gRPC client for manar-ai. Vitest. pnpm 11 workspace
(`packages/*`), Node 24.

## Commands (verified 2026-09-17; unit tests and coverage 2026-10-09)

| Task                  | Command                                                                                                  | Baseline                                         |
| --------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Backing services      | `pnpm infra:up` (Compose `deploy/docker-compose.yml`) then `pnpm infra:openbao-init`                     | all healthy                                      |
| Lint                  | `pnpm lint` (gating, no auto-fix; `pnpm lint:fix` to fix)                                                | clean on tracked source                          |
| Typecheck             | `pnpm typecheck` (builds `packages/manar-ai-client` and `packages/sdk-node` first, then api + scripts)   | pass                                             |
| Unit tests            | `pnpm test` / `pnpm test:cov` (CI; fails under the floor in `vitest.config.mts`)                         | 62 files, 663 tests; lines 52.9%, branches 50.5% |
| E2E tests             | `pnpm test:e2e` (needs the stack and OpenBao PKI; stop any host worker first, the specs start their own) | 27 files, 168 tests                              |
| Build                 | `pnpm build`                                                                                             | pass                                             |
| API                   | `pnpm start:dev` / `pnpm start:prod` — HTTP `:3000`, agent mTLS `:3443`                                  |                                                  |
| Temporal worker       | `pnpm worker:dev` / `pnpm worker:prod`                                                                   |                                                  |
| OpenFGA model tests   | `pnpm fga:test`                                                                                          |                                                  |
| Prisma client         | `pnpm db:generate` (runs on install)                                                                     |                                                  |
| Control DB migrations | `pnpm db:migrate:control` (dev) / `pnpm db:migrate:control:deploy`                                       | 3 migrations                                     |
| Tenant DB migrations  | `pnpm manar tenants:migrate` (every ACTIVE tenant; run on every upgrade, after the control migrations)   |                                                  |
| Demo reseed           | `pnpm manar demo:seed` (idempotent; only needed after wiping the OpenBao volume)                         |                                                  |

**OpenBao is persistent locally** (file storage on the `manar-openbao-data` volume;
`deploy/openbao-entrypoint.sh` inits once and unseals on every start). Restarts keep the CA and
the `secret/tools/*` credentials. The unseal key and initial root token are in
`~/.manar-openbao/` (host only, never in a repo); apps keep `OPENBAO_TOKEN=manar-dev-root-token`.
`pnpm infra:openbao-init` is needed once per fresh volume and skips what exists (it never
regenerates an existing CA). If the volume is wiped, the PKI is gone: re-run it, restart the API
and re-enroll agents; `/health/ready` reports `openbao` unhealthy until then (it probes the
intermediate's `ca_chain`). CI still runs OpenBao in `-dev` mode (`.gitlab-ci.yml`).

`src/generated/**` is Prisma output and is ignored by eslint. `pnpm demo:agent` runs the scripted
demo against `packages/demo-soc-tools`; with `test/complete-demo.e2e-spec.ts` it is the rehearsed
fallback for 11 November and must keep passing through every phase (Addendum 01 §A). It does not
load the API's `.env` (variables it reads: `.env.demo-agent.example`) and verifies the evidence
bundle through `POST /evidence/verify`, never with the signing secret.

## Architecture map

| Area               | Path                                                                                                                                          | Notes                                                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Bootstrap          | `src/main.ts`, `src/worker.main.ts`, `src/cli.ts`                                                                                             | Two Nest apps in one process: human HTTP (JWT) and agent mTLS                                                                                   |
| Metrics            | `src/metrics/metrics.ts`                                                                                                                      | Prometheus on internal `METRICS_PORT` (9464): HTTP histogram per listener, decision counters; worker uses Temporal's exporter                   |
| Human auth         | `src/auth/`, `src/keycloak/`                                                                                                                  | Keycloak JWT; tenant resolved from the issuer                                                                                                   |
| Tenancy            | `src/database/`, `src/tenants/`, `prisma/control.prisma`                                                                                      | One PostgreSQL database per tenant; LRU client cache                                                                                            |
| Agent identity     | `src/agents/`, `src/agent-mtls/`, `src/openbao/`                                                                                              | CSR enrollment, OpenBao-held CA, SAN `agent://<tenant>/<agent>`, guard on `/agent/v1/*`                                                         |
| Tasks + delegation | `src/tasks/`, `src/delegation/`                                                                                                               | TTL, allowed tool actions, execution limits, parent chain                                                                                       |
| Authorization      | `src/authorization/` (`model/manar.fga`), `src/policy/`, `src/risk/`                                                                          | Kill switches → task → OpenFGA `can_use` (3 s allow cache) → JSON policy rules → deterministic risk score → `Decision` row committed (ADR-0006) |
| Approvals          | `src/approvals/`, `src/temporal/workflows/approval.workflow.ts`                                                                               | Temporal workflow, single-use grant bound to a parameter hash                                                                                   |
| Tool gateway       | `src/tools/` (`credential-broker.service.ts`, `http-tool.adapter.ts`, `mcp-tool.adapter.ts`, `microsoft-tool.adapter.ts`), `src/common/ssrf/` | Executes on the agent's behalf; Microsoft Graph/Defender catalog (ADR-0004) tested against the DEMO FIXTURE only, not a live tenant             |
| Kill switches      | `src/kill-switches/`, `src/ai-systems/` (docs/decision-path.md)                                                                               | In-memory, 2 s bound, Valkey epoch check; AI system SUSPENDED/RETIRED blocks its agents                                                         |
| Hosts              | `src/hosts/` (docs/hosts.md)                                                                                                                  | Install keys (hash only, one conditional UPDATE), `POST /hosts/register`, approval rules, pending rekey needs an admin                          |
| Edge               | `src/edge/`, `src/tools/host-actions.ts` (docs/edge.md)                                                                                       | WireGuard peer registry (control DB) cut on every stop condition, gateway sync API on the HTTP port only, egress allow-list                     |
| Rate limiting      | `src/rate-limit/` (docs/decision-path.md)                                                                                                     | GCRA in Valkey, per tenant and per agent; `TokenLeaseService` budget leases (not wired yet)                                                     |
| Idempotency        | `src/idempotency/`                                                                                                                            | Redis `SET NX` interceptor on selected routes                                                                                                   |
| Licensing          | `src/licensing/` (`keys/<kid>.pub`), `scripts/license-issue.mjs`, `docs/licensing.md`                                                         | Signed offline licence (Ed25519 JWS), soft limits only: status, log, metrics, `/platform/v1/license`, `/tenant/license`; never blocks           |
| Audit + evidence   | `src/audit/` (hash chain, Kafka `manar.audit-events`, OpenSearch `manar-audit-events`, OCSF), `src/evidence/`                                 | Linear SHA-256 chain; evidence export                                                                                                           |
| Agent runtime      | `src/agent-runtime/` (ADR-0002)                                                                                                               | LLM proxy, per-task tool manifest, governed MCP server on the mTLS listener; `ToolInvocationService` is shared with tools/invoke                |
| Cloud agents       | `src/cloud-mcp/` (docs/cloud-agents.md)                                                                                                       | Public OAuth MCP endpoint `/mcp/<tenant>/<agent>` on the HTTP app (off by default); Copilot Studio and ChatGPT via the tenant realm             |
| AI advisory        | `src/ai-advisory/`, `packages/manar-ai-client`                                                                                                | gRPC to manar-ai; never on the decision path (`src/authorization/decision-path-dependencies.spec.ts`)                                           |
| Packages           | `packages/sdk-node` (TS agent SDK), `packages/demo-soc-tools` (fixture SIEM/EDR/IAM), `packages/manar-ai-client` (vendored proto client)      |                                                                                                                                                 |
| Deploy             | `deploy/docker-compose.yml`, `deploy/helm/{manar-api,manar-api-worker,demo-soc-tools}`, `deploy/openbao-init.mjs`                             |                                                                                                                                                 |

Longer per-area docs are in `docs/*.md`. Treat them as leads; the code and tests win.

## Rules for this repo

- **Decision path:** the synchronous authorization path may touch only PostgreSQL, Redis and
  OpenFGA (plus in-process policy evaluation). No LLM, Kafka, OpenSearch or manar-ai call.
  `decision-path-dependencies.spec.ts` enforces the import graph; extend it, never weaken it.
- **Fail closed:** any failure of identity, tenant resolution, authorization, capability
  verification, revocation lookup, limits store or kill-switch state is DENY with reason
  `enforcement_dependency_unavailable`. Every such control gets a negative test.
- **Tenant scoping:** every query, cache key, topic payload and index document carries the tenant.
- **Secrets:** never log tokens, credentials, full capability tokens or raw payloads. Log ids and
  hashes.

## Migrations

- Prisma only, two schemas: `prisma/control.prisma` (migrations in `prisma/control/migrations`)
  and `prisma/tenant.prisma` (migrations in `prisma/tenant/migrations`, applied per tenant
  database by `TenantDatabaseManager` with `prisma migrate deploy` at provisioning).
- Never edit an applied migration. Every migration ships with a rollback note in the PR.
  Destructive migrations (dropping columns or tables, narrowing types) need an ADR.
- New tables include timestamps and the indexes their queries need. Decision, approval and audit
  records are append-only apart from explicit state columns.

## Testing conventions

- Unit specs next to the code: `src/**/*.spec.ts` (Vitest).
- E2E specs in `test/*.e2e-spec.ts` against the real Compose stack
  (`test/vitest.config.e2e.mts`).
- Security controls need negative-path tests (deny, expiry, revocation, tamper, dependency down).

## ADRs and CI

- ADRs: `docs/adr/ADR-NNNN-<slug>.md` from `ADR-0000-template.md`. Written: ADR-0001 (the
  thesis), ADR-0002 (LLM proxy, tool manifest, governed MCP server; its "Agent contract" section is the agent API), ADR-0003 (capability token format, deferred), ADR-0004 (Microsoft connectors and credentials),
  ADR-0005 (Cedar, proposed and conditional), ADR-0006 (decision record commits with its reservation; grant redemption re-decides), ADR-0007 (an MCP client completes an approved action by calling the same tool again), ADR-0008 (read-only console assistant), ADR-0009 (watcher: agent quarantine, built-in Manar connector, human-only release), ADR-0010 (platform API for manar-fleet and the signed heartbeat), ADR-0011 (helpdesk and joiner/leaver Graph actions; a temporary password goes only to its approver, KV v1 handover), ADR-0012 (typed GitLab connector for one project: approvals bound to the reviewed state), ADR-0013 (per-tenant catalog: feature flags, packs, LLM route, enforced fail closed). Workspace ADR-001…009 in `../docs/adr/` remain the cross-repo record.
- CI: GitLab (`.gitlab-ci.yml`): lint, typecheck, unit (PostgreSQL + Redis), e2e (full services),
  build, images, gitleaks, semgrep, Trivy, SBOM, Helm render + kubeconform + kube-linter.
