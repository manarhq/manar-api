import type { CatalogService } from './catalog.service';

/** Test stand-in for an unmanaged tenant: every feature on, no pack checks fail, default model. */
export const allowAllCatalog = (): CatalogService =>
  ({
    taskDenyReason: () => Promise.resolve(null),
    llmGate: () => Promise.resolve({ route: null }),
    recordTokens: () => Promise.resolve(0),
  }) as unknown as CatalogService;
