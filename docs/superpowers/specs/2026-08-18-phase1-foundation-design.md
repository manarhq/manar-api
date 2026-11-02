# Phase 1: Foundation — Design

Status: Approved for planning
Scope: `manar-api`, `manar-web`, `manar-ai` (cross-repo)
Owner: Mohamed Nofal

## Purpose

Establish the toolchain, configuration, logging, testing, containerization,
and CI baseline across all three Manar repositories before any domain logic
(tenancy, identity, tasks, policy, etc.) is implemented. This is Phase 1 of
the master implementation plan (see repo root `Decisions.md` for the
answered architecture questionnaire that precedes this spec). No feature
work belongs in this phase — only the scaffolding every later phase will
build on.

## Current state (as of 2026-08-18)

- `manar-api`: stock `nest new` output. Express adapter, Jest, no env
  validation, no logging setup, no Dockerfile, no CI. Git repo initialized,
  pushed to `origin/main` on GitLab (`manar/manar-api.git`).
- `manar-web`: stock `create-next-app` output (Next.js 16, React 19,
  Tailwind 4). No env validation, no Dockerfile, no CI. Git repo
  initialized, pushed to `origin/main` on GitLab (`manar/manar-web.git`).
- `manar-ai`: empty directory. Not a git repo yet. GitLab remote
  `manar/manar-ai.git` exists (created per decision #8) but nothing has
  been pushed to it.

Local toolchain available: Node 24, pnpm 11, Python 3.13, Docker 29 /
Compose v5.

## Out of scope

- Any domain module (tenancy, agents, tasks, policy, risk, audit, etc.)
- Local infra docker-compose (Postgres/Keycloak/OpenFGA/OpenBao/Kafka/
  Temporal/Redis/OpenSearch) — separate sub-project, next after this one
- Kubernetes/Helm manifests — Section 96 Phase 1 lists Docker, not Helm;
  deferred to a later infra phase once there's a real service to deploy
- SAST/secret-scanning/container-scanning in CI — Phase 12 per the master
  prompt; wiring empty/toothless scan stages now would be worse than not
  having them
- gRPC contracts between `manar-api` and `manar-ai` — Phase 10/AI phase

## Design

### A. Toolchain & repo hygiene

**manar-api**

- Swap the Express adapter for `@nestjs/platform-fastify` (decision #5).
- `tsconfig.json`: enable `strict`, `noUncheckedIndexedAccess`,
  `noImplicitOverride`; keep `esModuleInterop`. No `any` in hand-written
  code.
- Add Husky + lint-staged + Commitlint (decision #70), Conventional Commits
  enforced on commit-msg hook. Pre-commit hook runs lint-staged only
  (ESLint --fix + Prettier on staged files) — kept fast; full test suite
  stays in CI per Section 78.

**manar-web**

- Same Husky/lint-staged/Commitlint setup as manar-api.
- `tsconfig.json`: `strict: true` (Next.js default already sets this;
  verify no `any` leaks in scaffold).

**manar-ai**

- `git init`; set `origin` to `ssh://git@git.example.com/manar/manar-ai.git`.
- Bootstrap FastAPI skeleton under `app/` per Section 38's layer list
  (only `api/`, `domain/`, `observability/` populated at this phase — the
  rest are empty-with-`__init__.py` placeholders documented as "populated
  in later phases", not fake modules).
- Package manager: `uv` (Astral). Rationale: fast, single lockfile
  (`uv.lock`), first-class `pyproject.toml`-based, current recommended
  tool for new Python projects as of 2025/2026 or later; equivalent role
  to pnpm's lockfile discipline on the TS side. Not specified in
  `Decisions.md`, so recorded here and in
  `manar-ai/docs/dependency-decisions.md` rather than asked as a blocking
  question.
- `ruff` (lint + format) and `mypy` (type check) via `pre-commit`, mirroring
  the Husky/lint-staged role on the TS repos.

### B. Typed configuration

- `manar-api`: a `ConfigModule` with per-domain Zod schemas (e.g.
  `AppConfigSchema` for now — just `PORT`, `NODE_ENV`, `LOG_LEVEL`; later
  phases add their own schemas alongside their own modules rather than
  growing one giant schema). Startup fails fast with a clear error listing
  every invalid/missing var. No `process.env` reads outside this module.
- `manar-web`: a small `env.ts` using Zod to validate the server-side env
  vars it needs at this stage (currently none beyond `NODE_ENV`) —
  structure established so Phase 11 doesn't retrofit it.
- `manar-ai`: `pydantic-settings` `BaseSettings` subclass, same fail-fast
  behavior on invalid config.

### C. Logging

- `manar-api` / `manar-web`: Winston (decision #75), structured JSON
  output. A Nest interceptor/middleware assigns and logs a correlation ID
  per request (`x-correlation-id`, generated if absent). Two log
  "channels" conceptually: operational (service lifecycle, infra
  connectivity) vs. security-relevant — but OCSF mapping itself is Phase 9;
  this phase just ensures every log line is structured JSON with a
  correlation ID field so Phase 9 can filter/route it.
- `manar-ai`: Python `logging` configured with a JSON formatter
  (`python-json-logger` or equivalent current-recommended library) and the
  same correlation-ID convention (read from an incoming header, generated
  if absent), so traces from `manar-api` calls can be joined later.

### D. Testing

- `manar-api`: replace Jest with Vitest (decision #65) — remove
  `ts-jest`/`jest` deps and the `jest` config block in `package.json`;
  follow NestJS's current official Vitest integration guidance (to be
  looked up at implementation time per Section 5, not guessed). One
  passing test for the health controller.
- `manar-web`: add Vitest + React Testing Library, one passing smoke test.
- `manar-ai`: `pytest`, one passing test for the health endpoint.
- No Playwright/E2E yet — nothing UI-navigable exists until later phases.

### E. Docker + health endpoints

- Each repo gets a multi-stage `Dockerfile`: build stage with full
  toolchain, runtime stage minimal (`node:24-alpine` / `python:3.13-slim`),
  non-root user, `HEALTHCHECK` instruction, no build tools or dev deps in
  the final image. `.dockerignore` per repo (excludes `node_modules`,
  `.git`, `.env*`, test artifacts).
- `manar-api`: `GET /health/live` (process liveness, always 200 once up)
  and `GET /health/ready` (currently a stub returning ready — no real
  dependency yet to check; later phases add DB/Redis/etc. checks here
  rather than inventing a second endpoint).
- `manar-web`: Next.js has no natural "readiness" concept the way a
  backend does; expose a minimal `/api/health` route for container health
  checks.
- `manar-ai`: `GET /health/live` and `GET /health/ready` in FastAPI,
  same stub-readiness rationale as manar-api.

### F. CI skeleton

- One `.gitlab-ci.yml` per repo: stages `lint → typecheck → test → build`.
  `manar-api`/`manar-web` use pnpm with GitLab's pnpm cache pattern;
  `manar-ai` uses `uv`. No deploy stage yet (nothing to deploy to).
  Security scanning stages are explicitly deferred (see Out of scope) —
  not stubbed with `allow_failure: true` placeholders, since that reads as
  "done" when it isn't.

### G. Documentation

- `docs/dependency-decisions.md` in each repo, populated as dependencies
  are actually added during implementation (Technology / Purpose /
  Version / License / Docs consulted / Install method / Why / Alternatives
  considered), per Section 5. Not written retroactively at the end.

## Testing strategy for this phase

Each repo must, at the end of Phase 1:

- `pnpm lint` / `ruff check` passes
- `pnpm typecheck` (`tsc --noEmit`) / `mypy` passes
- `pnpm test` / `pytest` passes (the one smoke test per repo)
- `docker build` succeeds and the resulting container responds 200 on both
  health endpoints when run
- A commit with a malformed message is rejected by Commitlint (manual
  verification, not an automated test)
- Starting the service with a required env var unset fails fast with a
  readable error (manual verification)

## Error handling

Not applicable at this phase beyond "fail fast on invalid config" — no
business error model yet (that's Section 8, introduced when the first real
endpoint exists in Phase 2+).

## Open questions for later phases (not blocking this one)

- Exact GitLab CI runner availability/tags — assumed default shared
  runners for now; revisit if self-hosted runners are required.
- Whether `manar-web`'s health route needs any auth — not yet, nothing
  sensitive is exposed by it.
