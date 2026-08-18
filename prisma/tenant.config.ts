import 'dotenv/config';
import { defineConfig } from 'prisma/config';

// Prisma CLI configuration for the tenant schema (prisma/tenant.prisma).
//
// Unlike the control schema, this file's `datasource.url` is deliberately
// re-pointed at a *different* database on every invocation:
// `TenantDatabaseManager.provisionTenant` spawns `prisma migrate deploy
// --config prisma/tenant.config.ts` as a child process with `DATABASE_URL`
// set to that specific tenant's resolved connection string. There is no
// single "the tenant database" this config can name up front.
export default defineConfig({
  schema: 'prisma/tenant.prisma',
  migrations: {
    path: 'tenant/migrations',
  },
  datasource: {
    url: process.env.DATABASE_URL ?? '',
  },
});
