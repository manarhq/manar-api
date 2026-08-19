import { z } from 'zod';

/**
 * Phase 15a (Section 53) — the tenant-DB `DataClassification` enum
 * (`prisma/tenant.prisma`), mirrored here as a plain TS/Zod artifact so
 * every consumer that isn't itself a Prisma query (the policy rule schema,
 * `AiAdvisoryClient`'s residency gate, DTOs) can reference the same four
 * values without importing the generated tenant-client type — the same
 * "small shared constant, not a re-derivation" posture
 * `src/auth/roles.ts`'s `ROLES` establishes for `Role`.
 *
 * **Ordered least-to-most sensitive** — `CLASSIFICATION_RANK` (see
 * `RiskEngine`) relies on this array's order, not just its membership.
 *
 * `INTERNAL` is `ToolAction.classification`'s schema default — deliberately
 * not `PUBLIC` (Section 53: "the safer default"). A `ToolAction` row
 * written before this phase existed defaults to `INTERNAL` on backfill via
 * the migration itself (see migration
 * `20260819_add_data_classification/migration.sql`), never `PUBLIC`.
 */
export const DATA_CLASSIFICATIONS = [
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
] as const;

export type DataClassification = (typeof DATA_CLASSIFICATIONS)[number];

export const DataClassificationSchema = z.enum(DATA_CLASSIFICATIONS);

export const DEFAULT_DATA_CLASSIFICATION: DataClassification = 'INTERNAL';
