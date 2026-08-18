# Dependency decisions

Tracks every dependency added to `manar-api`, as it is added, per
`docs/superpowers/specs/2026-08-18-phase1-foundation-design.md` Section G.
Not written retroactively — each entry reflects the research done at the
time the dependency was introduced.

## Phase 1: Foundation

### @nestjs/platform-fastify

- **Purpose**: HTTP adapter, replacing `@nestjs/platform-express`.
- **Selected version**: `^11.2.1`
- **License**: MIT
- **Official docs consulted**: <https://docs.nestjs.com/techniques/performance> (Fastify adapter migration guide)
- **Installation method**: `pnpm add @nestjs/platform-fastify`
- **Why selected**: Decision #5 in the master questionnaire. Fastify is
  roughly 2x faster than Express on Nest's own benchmarks and is a
  first-class, officially supported Nest adapter.
- **Alternatives considered**: Staying on Express (rejected — the
  decision to move to Fastify predates this phase and was already made
  in `Decisions.md`).

### fastify

- **Purpose**: Direct dependency on Fastify's own package, needed
  because application code (`src/logging/logging.interceptor.ts`)
  imports `FastifyRequest`/`FastifyReply` types directly. Without this,
  `fastify` is only a transitive dependency of
  `@nestjs/platform-fastify` and pnpm's strict `node_modules` layout
  does not expose it to application code (a "phantom dependency").
- **Selected version**: `^5.12.0` (matches the version
  `@nestjs/platform-fastify@11.2.1` resolves internally)
- **License**: MIT
- **Official docs consulted**: <https://docs.nestjs.com/techniques/performance>
- **Installation method**: `pnpm add fastify`
- **Why selected**: Required transitively; made explicit for correct
  type resolution under pnpm's strict linking.
- **Alternatives considered**: None — this is Fastify itself.

### @nestjs/config

- **Purpose**: Typed configuration module (`ConfigModule`/`ConfigService`),
  wrapped with a custom Zod `validate()` function in
  `src/config/config.module.ts`.
- **Selected version**: `^4.0.4`
- **License**: MIT
- **Official docs consulted**: <https://docs.nestjs.com/techniques/configuration>
  (in particular the "Custom validate function" section, which is the
  documented extension point used here instead of the built-in Joi
  option)
- **Installation method**: `pnpm add @nestjs/config`
- **Why selected**: The standard, officially maintained Nest package
  for environment configuration; supports plugging in any validation
  library via `validate()`.
- **Alternatives considered**: Hand-rolled `process.env` wrapper
  (rejected — reinvents `.env` loading/merging that `@nestjs/config`
  already does correctly, e.g. runtime env vars taking precedence over
  `.env` file values).

### zod

- **Purpose**: Schema validation for environment variables
  (`src/config/env.validation.ts`, `AppConfigSchema`).
- **Selected version**: `^4.4.3`
- **License**: MIT
- **Official docs consulted**: <https://zod.dev> (schema/`safeParse` API
  verified directly against the installed version before use, since v4
  changed some APIs from v3)
- **Installation method**: `pnpm add zod`
- **Why selected**: Decision-adjacent to `@nestjs/config`'s documented
  custom-validator extension point; TypeScript-first, zero-dependency,
  gives a typed config object (`z.infer`) plus itemized, readable parse
  errors for the fail-fast startup requirement.
- **Alternatives considered**: Joi (the `@nestjs/config` built-in
  option — rejected: no static type inference); `class-validator` +
  `class-transformer` (the pattern shown in Nest's own docs example —
  rejected: decorator/class-based, heavier for a handful of scalar env
  vars, and not the project's established validation idiom).

### winston

- **Purpose**: Structured JSON logging.
- **Selected version**: `^3.19.0`
- **License**: MIT
- **Official docs consulted**: <https://docs.nestjs.com/techniques/logger>
  (names Winston as the recommended production logging module) and
  <https://github.com/winstonjs/winston>
- **Installation method**: `pnpm add winston`
- **Why selected**: Decision #75 in the master questionnaire.
- **Alternatives considered**: Pino (faster, but not the decided
  option); Nest's built-in `Logger` alone (rejected — no structured
  JSON output).

### nest-winston

- **Purpose**: Wires Winston into Nest's DI and `LoggerService`
  interface (`WinstonModule`, `WINSTON_MODULE_NEST_PROVIDER`,
  `WINSTON_MODULE_PROVIDER`) so `app.useLogger()` and constructor
  injection both work.
- **Selected version**: `^1.10.2`
- **License**: MIT
- **Official docs consulted**: <https://github.com/gremo/nest-winston>
  (README — Nest's own docs only name Winston generically and defer to
  a community integration for the actual wiring)
- **Installation method**: `pnpm add nest-winston`
- **Why selected**: The de facto standard Nest+Winston integration
  (actively maintained, widely used); avoids hand-rolling a
  `LoggerService` adapter.
- **Alternatives considered**: Hand-written `WinstonLogger implements
LoggerService` (rejected — `nest-winston` already does this
  correctly, including `forRootAsync()` for injecting `ConfigService`).

### vitest / @vitest/coverage-v8

- **Purpose**: Test runner, replacing Jest entirely (unit specs via
  `vitest.config.mts`, e2e specs via `test/vitest.config.e2e.mts`).
- **Selected version**: `^4.1.10` (both)
- **License**: MIT
- **Official docs consulted**: NestJS has no dedicated Vitest recipe
  page on <https://docs.nestjs.com> as of this phase (confirmed by
  checking the docs site's own content source,
  <https://github.com/nestjs/docs.nestjs.com>, and its `recipes/`
  directory). The authoritative current reference is instead the
  official `nestjs/nest` repository's own Fastify sample app,
  <https://github.com/nestjs/nest/tree/master/sample/10-fastify>, which
  itself runs on Vitest 4 with `vitest.config.mts` /
  `vitest.config.e2e.mts` — the exact layout this project follows.
  Confirmed empirically that Vitest's esbuild-based transform handles
  `emitDecoratorMetadata` without an SWC plugin (tested directly with
  `AppController`'s constructor-injected `AppService`).
- **Installation method**: `pnpm add -D vitest @vitest/coverage-v8`
- **Why selected**: Decision #65. Matches the pattern NestJS's own
  current sample apps use.
- **Alternatives considered**: `vitest` + `unplugin-swc` +
  `@swc/core` (the pattern documented in most third-party
  NestJS+Vitest blog posts, e.g. Trilon's `nest-vitest` sample —
  initially installed, then removed after confirming it was
  unnecessary: current Vitest/esbuild already emits correct decorator
  metadata, and the official Nest sample doesn't use it either).

### husky

- **Purpose**: Git hooks manager — `pre-commit` (lint-staged) and
  `commit-msg` (Commitlint).
- **Selected version**: `^9.1.7`
- **License**: MIT
- **Official docs consulted**: <https://typicode.github.io/husky/get-started.html>
- **Installation method**: `pnpm add -D husky` + `pnpm exec husky init`
  (`prepare` script wired into `package.json`, hooks under `.husky/`)
- **Why selected**: Decision #70. Current standard Git-hooks manager
  for Node projects.
- **Alternatives considered**: Plain Git hooks committed by hand
  (rejected — Husky handles the `core.hooksPath` wiring and
  team-wide install-on-clone via the `prepare` script).

### lint-staged

- **Purpose**: Runs ESLint `--fix` and Prettier only against staged
  files in the pre-commit hook, keeping it fast.
- **Selected version**: `^17.3.0`
- **License**: MIT
- **Official docs consulted**: <https://github.com/lint-staged/lint-staged>
- **Installation method**: `pnpm add -D lint-staged` (config in
  `.lintstagedrc.json`)
- **Why selected**: Standard companion to Husky for staged-file-only
  linting; explicitly named in the design spec (Section A) to keep
  pre-commit fast while the full suite stays in CI.
- **Alternatives considered**: A hand-written shell script (Husky's
  own docs show a two-line Prettier-only example) — rejected: doesn't
  cover ESLint `--fix`, and lint-staged's glob/config handling is
  better tested.

### @commitlint/cli / @commitlint/config-conventional

- **Purpose**: Enforces Conventional Commits on the `commit-msg` hook.
- **Selected version**: `^21.2.2` (both)
- **License**: MIT
- **Official docs consulted**: <https://commitlint.js.org/guides/getting-started>
  and <https://commitlint.js.org/guides/local-setup> (Husky v9
  `commit-msg` wiring)
- **Installation method**: `pnpm add -D @commitlint/cli @commitlint/config-conventional`
  (config in `commitlint.config.mjs`; `.mjs` extension used per
  Commitlint's own Node v24 ESM-loading guidance, since this
  package's `package.json` has no `"type": "module"`)
- **Why selected**: Decision #70; Conventional Commits enforcement
  explicitly required by the design spec.
- **Alternatives considered**: None — Commitlint is the standard tool
  for this and was specified directly.

## Phase 2: Persistence & Tenancy

### postgres (Docker image)

- **Purpose**: Local dev Postgres server (`deploy/docker-compose.yml`) —
  hosts the control DB and every tenant DB as separate databases on one
  server for local dev.
- **Selected version**: `postgres:18.6-alpine`
- **License**: PostgreSQL License (permissive, MIT-like)
- **Official docs consulted**: Docker Hub's `library/postgres` tags API
  (<https://hub.docker.com/_/postgres/>) queried directly
  (`hub.docker.com/v2/repositories/library/postgres/tags`) to confirm the
  current stable major version and latest patch as of this phase (18.6,
  published 2026-08-16) rather than trusting a possibly-stale web search
  summary — Postgres 18 GA'd September 2025, making it the current stable
  major as of this phase (August 2026).
- **Installation method**: `docker compose -f deploy/docker-compose.yml up`
- **Why selected**: A pinned, specific patch version (not `latest`) per the
  design spec, for reproducible local dev across machines/time. `-alpine`
  variant for a smaller pulled image.
- **Alternatives considered**: `postgres:17` (rejected — 18 is current
  stable, no reason to pin an older major for a fresh phase);
  `postgres:latest` (rejected explicitly by the design spec — unpinned
  tags silently change over time).

### prisma / @prisma/client / @prisma/adapter-pg

- **Purpose**: ORM/query builder and CLI (`prisma`), generated typed client
  (`@prisma/client`, the runtime package the two generated clients under
  `src/generated/` depend on), and the Postgres driver adapter
  (`@prisma/adapter-pg`) that Prisma 7's client construction requires.
- **Selected version**: `^7.9.1` (all three, matched to avoid version
  skew between the CLI and the generated clients)
- **License**: Apache-2.0
- **Official docs consulted**: <https://www.prisma.io/docs/orm/prisma-schema/overview/location>
  (multi-file vs. multi-schema — confirmed the project needs _separate_
  schema+config pairs, not the `prismaSchemaFolder` preview feature, which
  only splits one schema across files), <https://www.prisma.io/docs/orm/reference/prisma-config-reference>
  (confirmed `--config` lets each schema have its own `migrations.path`
  and `datasource.url`), <https://www.prisma.io/docs/guides/frameworks/nestjs>
  (current NestJS integration pattern — `prisma-client` generator,
  `PrismaPg` driver adapter), and direct empirical verification against the
  installed 7.9.1 CLI (Prisma 7 is a major release from July 2026; the
  client generator defaults to ESM output, which required explicitly
  setting `moduleFormat = "cjs"` in both generator blocks once this project's
  CommonJS Nest setup broke against the ESM default — confirmed via
  <https://github.com/prisma/prisma/pull/27828> and reproduced locally).
- **Installation method**: `pnpm add prisma @prisma/client @prisma/adapter-pg pg dotenv`;
  `pnpm approve-builds` required for `prisma`/`@prisma/engines`'s install
  scripts (pnpm's default blocks dependency install scripts — see
  `pnpm-workspace.yaml`'s `allowBuilds`).
- **Why selected**: Explicitly required by the design spec — two
  independent Prisma schemas (`prisma/control.prisma`, `prisma/tenant.prisma`),
  each with its own generated client (`src/generated/control-client`,
  `src/generated/tenant-client`) and its own `prisma.config.ts`
  (`prisma/control.config.ts`, `prisma/tenant.config.ts`), selected via
  each CLI invocation's `--schema`/`--config` flags (see `db:generate`,
  `db:migrate:control` in `package.json`). Prisma 7 requires a driver
  adapter for every client (no built-in query engine any more —
  `new PrismaClient()` with no arguments throws), which is why
  `@prisma/adapter-pg` + `pg` are direct dependencies rather than Prisma
  managing its own connection internally.
- **Alternatives considered**: Drizzle ORM (rejected — Prisma is this
  project's decided ORM per the master questionnaire; not revisited here);
  staying on a pre-7 Prisma major (rejected — 7.9.1 is current stable, and
  the driver-adapter model is exactly the "construct a client with a
  runtime connection string" capability `TenantDatabaseManager.getClient`
  needs, via `datasourceUrl`'s Prisma-7 equivalent, `new PrismaPg({
connectionString })`).

### pg / @types/pg

- **Purpose**: Raw Postgres client, used directly (not through Prisma) for
  administrative operations that don't fit a Prisma-managed connection:
  issuing `CREATE DATABASE` (which cannot run inside a transaction block)
  and `DROP DATABASE` (`TenantDatabaseManager.createTenantDatabase` /
  `dangerouslyDropTenantDatabase`). Also the underlying driver
  `@prisma/adapter-pg` wraps, made a direct (non-transitive) dependency for
  the same phantom-dependency reason `fastify` was in Phase 1.
- **Selected version**: `pg@^8.23.0`, `@types/pg@^8.23.1` (dev)
- **License**: MIT
- **Official docs consulted**: <https://node-postgres.com/> (`Client`
  API — `connect()`/`query()`/`end()`)
- **Installation method**: `pnpm add pg` / `pnpm add -D @types/pg`
- **Why selected**: The standard, de facto Postgres driver for Node;
  required directly by `@prisma/adapter-pg`'s own peer dependency and by
  `TenantDatabaseManager`'s administrative DDL operations.
- **Alternatives considered**: `postgres` (the `postgres.js` package —
  rejected: `@prisma/adapter-pg` is built specifically on `pg`, and using a
  second driver for the raw-admin path would mean maintaining two
  Postgres client configurations instead of one).

### dotenv

- **Purpose**: Loads `.env` into `process.env` for the Prisma CLI config
  files (`prisma/control.config.ts`, `prisma/tenant.config.ts`), which run
  as standalone processes outside Nest's `ConfigModule` (which does its own
  independent `.env` loading via `@nestjs/config` for the running app).
- **Selected version**: `^17.4.2`
- **License**: BSD-2-Clause
- **Official docs consulted**: <https://www.prisma.io/docs/orm/reference/prisma-config-reference>
  (shows `import 'dotenv/config'` as the recommended first line of
  `prisma.config.ts`)
- **Installation method**: `pnpm add dotenv` (a regular dependency, not
  dev-only: `TenantDatabaseManager.provisionTenant` spawns `prisma migrate
deploy` — which loads `prisma/tenant.config.ts`, which imports
  `dotenv/config` — as a runtime child process, including in production)
- **Why selected**: Was already a transitive dependency of `@nestjs/config`
  and `prisma`, but pnpm's strict `node_modules` layout doesn't expose
  transitive dependencies to application-authored code (the same phantom-
  dependency reasoning as `fastify` in Phase 1) — made explicit.
- **Alternatives considered**: None — this is what Prisma's own docs use
  for CLI-time env loading.

### nest-commander

- **Purpose**: `pnpm manar tenant:create ...` CLI (`src/cli.ts`,
  `src/cli/`) — the only way to provision a tenant this phase (Section 11).
- **Selected version**: `^3.20.1`
- **License**: MIT
- **Official docs consulted**: <https://github.com/jmcdo29/nest-commander>
  (README — `CommandRunner`/`@Command`/`@Option` pattern, `CommandFactory.run`)
  and `npm view nest-commander peerDependencies` (confirmed
  `^11.0.0` compatibility with this project's `@nestjs/core`/`@nestjs/common`
  before installing).
- **Installation method**: `pnpm add nest-commander`
- **Why selected**: Explicitly named by the design spec; the standard way
  to build CLI commands inside a Nest application with full DI access
  (reusing `DatabaseModule` rather than re-implementing tenant provisioning
  outside Nest's dependency graph).
- **Alternatives considered**: `nestjs-command` (a similarly-purposed
  community package — rejected: `nest-commander` is more actively
  maintained and is the package explicitly named in the design spec);
  a bare Node script bypassing Nest DI entirely (rejected — would need to
  hand-wire `ConfigService`/`ControlPrismaService`/`TenantDatabaseManager`
  construction, duplicating what `CliModule` already gives for free).

## Removed this phase

- `@nestjs/platform-express`, `@types/express` — superseded by the
  Fastify adapter (item above).
- `jest`, `ts-jest`, `@types/jest` — superseded by Vitest (item above).
