import 'dotenv/config';
import { defineConfig } from 'prisma/config';

// Prisma CLI configuration for the control schema (prisma/control.prisma).
// Read only by `prisma` CLI invocations (generate/migrate) — the running
// application never imports this file; it resolves its control DB
// connection through ConfigService + the generated client's driver adapter
// instead (see src/database/control-prisma.service.ts).
//
// `process.env.CONTROL_DATABASE_URL` is read directly (not via the `env()`
// helper) because `env()` throws when the variable is unset, which would
// break `prisma generate` in contexts where only client-code generation is
// needed and no real connection exists yet (e.g. a fresh checkout before
// `pnpm infra:up`).
export default defineConfig({
  schema: 'prisma/control.prisma',
  migrations: {
    path: 'control/migrations',
  },
  datasource: {
    url: process.env.CONTROL_DATABASE_URL ?? '',
  },
});
