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

## Removed this phase

- `@nestjs/platform-express`, `@types/express` — superseded by the
  Fastify adapter (item above).
- `jest`, `ts-jest`, `@types/jest` — superseded by Vitest (item above).
