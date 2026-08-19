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

/**
 * Phase 10c — the highest-sensitivity value among `classifications`, per
 * `DATA_CLASSIFICATIONS`'s own least-to-most-sensitive order. `undefined`
 * for an empty input (never a default value that could be mistaken for a
 * real resolved classification) — mirrors `AiAdvisoryClient`'s own
 * "`undefined` means unaffected, falls through to the ordinary
 * `allowExternalAi` gate" convention (see `residencyAllows`'s doc
 * comment). Used by `/incidents/summarize` and `/audit/investigate` to
 * derive one `classification` to pass into `AiAdvisoryClient` from a whole
 * *set* of `AuditEvent`s/`ToolAction`s, the same "a reader can always
 * re-derive an action's classification from the live `ToolAction` row"
 * posture docs/data-classification.md's "Out of scope" section documents
 * as always available, not a new capability.
 */
export function maxClassification(
  classifications: DataClassification[],
): DataClassification | undefined {
  return classifications.reduce<DataClassification | undefined>(
    (max, candidate) =>
      max === undefined ||
      DATA_CLASSIFICATIONS.indexOf(candidate) >
        DATA_CLASSIFICATIONS.indexOf(max)
        ? candidate
        : max,
    undefined,
  );
}
