import type { CatalogService } from './catalog.service';

/** Test stand-in for an unmanaged tenant: every feature on, no pack checks fail, default model. */
export const allowAllCatalog = (): CatalogService =>
  ({
    taskDenyReason: () => Promise.resolve(null),
    resolveTaskPack: (_t: string, _a: string, requested?: string) =>
      Promise.resolve(requested ?? null),
    hiddenTools: () => Promise.resolve([]),
    externalAiSwitchedOff: () => Promise.resolve(false),
    llmGate: () => Promise.resolve({ route: null, quota: null }),
    recordTokens: () => Promise.resolve(0),
  }) as unknown as CatalogService;
