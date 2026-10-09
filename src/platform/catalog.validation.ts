import { z } from 'zod';

/**
 * Per-tenant catalog (feature flags, packs, LLM route) that Manar staff set through manar-fleet.
 * Pure schemas: this file is reachable from the authorization decision path and imports zod only.
 */

/** Gated surfaces. Each one is off for the tenant when its flag is false. */
export const CATALOG_FEATURES = [
  /** The console assistant (`POST /assistant/chat`). */
  'assistant',
  /** Manar's built-in connector (`manar.activity.read`, `manar.agent.quarantine`) the watcher uses. */
  'watcher',
  /** Every pack-bound task (`Task.packId` set). */
  'packs',
  /** The agent LLM proxy (`/agent/v1/llm/chat/completions`). */
  'llm_proxy',
] as const;
export type CatalogFeature = (typeof CATALOG_FEATURES)[number];

/** Before the catalog existed every surface was on; an unmanaged tenant keeps that. */
export const FEATURE_DEFAULTS: Record<CatalogFeature, boolean> = {
  assistant: true,
  watcher: true,
  packs: true,
  llm_proxy: true,
};

export const PACK_ID = z.string().regex(/^[a-z][a-z0-9-]{1,62}$/);

/** `ollama` is local (the sovereignty path); the other two send prompts off the deployment. */
export const LLM_PROVIDERS = [
  'ollama',
  'azure_openai',
  'core42_compass',
] as const;
export type LlmProvider = (typeof LLM_PROVIDERS)[number];
export const EXTERNAL_PROVIDERS: readonly LlmProvider[] = [
  'azure_openai',
  'core42_compass',
];

const features = z
  .object(
    Object.fromEntries(
      CATALOG_FEATURES.map((f) => [f, z.boolean().optional()]),
    ) as Record<CatalogFeature, z.ZodOptional<z.ZodBoolean>>,
  )
  .strict();

const pack = z
  .object({
    id: PACK_ID,
    version: z.number().int().min(1).max(100_000),
    enabled: z.boolean(),
    /**
     * Agents that run this pack. Every task of a bound agent is a task of this pack, whatever
     * `Task.packId` says, so disabling the pack stops the agent. Bound by staff only.
     */
    agents: z.array(z.uuid()).max(100).default([]),
  })
  .strict();

/** One entry per pack id, and an agent runs at most one pack. */
const uniquePacks = <T extends { id: string; agents?: string[] }[]>(packs: T) =>
  new Set(packs.map((p) => p.id)).size === packs.length &&
  new Set(packs.flatMap((p) => p.agents ?? [])).size ===
    packs.reduce((n, p) => n + (p.agents?.length ?? 0), 0);

export const ModelConfigSchema = z
  .object({
    provider: z.enum(LLM_PROVIDERS),
    /** Ollama model tag, Azure deployment name or Compass model id. */
    model: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/),
    /** Staff's statement that this model runs in the UAE. Required for a UAE-resident tenant. */
    uaeResidency: z.boolean(),
    /** Tokens per calendar month (UTC) across the LLM proxy and the assistant; null = no quota. */
    monthlyTokenQuota: z
      .number()
      .int()
      .min(1)
      .max(1_000_000_000_000)
      .nullable(),
  })
  .strict();
export type ModelConfig = z.infer<typeof ModelConfigSchema>;

/** What is stored in `tenant_catalogs`. Parsed on every read; a row that fails denies. */
export const StoredCatalogSchema = z.object({
  features,
  packs: z
    .array(pack)
    .max(100)
    .refine(uniquePacks, 'duplicate pack id, or an agent bound to two packs'),
  model: ModelConfigSchema.nullable(),
});
export type StoredCatalog = z.infer<typeof StoredCatalogSchema>;

/**
 * `PATCH /platform/v1/tenants/:id/catalog`. Every part is optional: `features` merges key by key,
 * `packs` upserts by id, `model` replaces (null returns to the deployment default).
 */
export const CatalogPatchSchema = z
  .object({
    features: features.optional(),
    /** Upserted by id. `agents` omitted keeps the pack's current bindings. */
    packs: z
      .array(pack.extend({ agents: z.array(z.uuid()).max(100).optional() }))
      .max(100)
      .refine(uniquePacks, 'duplicate pack id, or an agent bound to two packs')
      .optional(),
    model: ModelConfigSchema.nullable().optional(),
  })
  .strict()
  .refine(
    (p) =>
      p.features !== undefined ||
      p.packs !== undefined ||
      p.model !== undefined,
    'nothing to change',
  );
export type CatalogPatch = z.infer<typeof CatalogPatchSchema>;
