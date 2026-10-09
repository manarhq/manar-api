import {
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { MANAR_TOOL } from '../tools/manar-actions';
import { CatalogDenied, CatalogService, catalogGate } from './catalog.service';
import { CatalogPatchSchema } from './catalog.validation';

type Row = {
  features: unknown;
  packs: unknown;
  model: unknown;
  updatedBy: string;
  updatedAt: Date;
} | null;

function make(
  opts: {
    row?: Row;
    rowError?: boolean;
    tenant?: { residency: string; allowExternalAi: boolean; status?: string };
    used?: number;
    usageError?: boolean;
  } = {},
) {
  const tenant = {
    id: 't1',
    status: 'ACTIVE',
    residency: 'UAE',
    allowExternalAi: false,
    ...opts.tenant,
  };
  type Upsert = {
    create: Record<string, unknown>;
    update: Record<string, unknown>;
  };
  const upsert = vi.fn<(arg: Upsert) => Promise<object>>(() =>
    Promise.resolve({}),
  );
  const control = {
    tenantCatalog: {
      findUnique: opts.rowError
        ? vi.fn().mockRejectedValue(new Error('control db down'))
        : vi.fn().mockResolvedValue(opts.row ?? null),
      upsert,
    },
    tenant: {
      findUnique: vi.fn().mockResolvedValue(tenant),
      findUniqueOrThrow: vi.fn().mockResolvedValue(tenant),
    },
  };
  const usage = {
    used: opts.usageError
      ? vi.fn().mockRejectedValue(new Error('redis down'))
      : vi.fn().mockResolvedValue(opts.used ?? 0),
    add: vi.fn().mockResolvedValue(1),
  };
  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const db = { tool: { findMany: vi.fn().mockResolvedValue([]) } };
  const service = new CatalogService(
    control as never,
    usage as never,
    { recordSafely } as never,
    { getClient: vi.fn().mockResolvedValue(db) } as never,
  );
  return { service, upsert, usage, recordSafely, db };
}

const row = (r: Partial<NonNullable<Row>>): Row => ({
  features: {},
  packs: [],
  model: null,
  updatedBy: 'manar-fleet',
  updatedAt: new Date(),
  ...r,
});

const azure = {
  provider: 'azure_openai',
  model: 'gpt-5-mini',
  uaeResidency: true,
  monthlyTokenQuota: null,
};

describe('CatalogService.taskDenyReason (decision path and agent runtime)', () => {
  it('lets an unmanaged tenant run its own agents and the watcher, as before the catalog', async () => {
    const { service } = make();
    await expect(service.taskDenyReason('t1', {}, 'graph')).resolves.toBe(null);
    await expect(service.taskDenyReason('t1', {}, MANAR_TOOL)).resolves.toBe(
      null,
    );
  });

  it('refuses a pack-bound task until staff enable that pack', async () => {
    const { service } = make();
    await expect(
      service.taskDenyReason('t1', { packId: 'it-helpdesk' }, 'graph'),
    ).resolves.toBe('pack_not_enabled');
  });

  it('allows a pack-bound task only for its own enabled pack', async () => {
    const { service } = make({
      row: row({
        packs: [
          { id: 'it-helpdesk', version: 1, enabled: true },
          { id: 'hr-joiner-leaver', version: 1, enabled: false },
        ],
      }),
    });
    await expect(
      service.taskDenyReason('t1', { packId: 'it-helpdesk' }),
    ).resolves.toBe(null);
    await expect(
      service.taskDenyReason('t1', { packId: 'hr-joiner-leaver' }),
    ).resolves.toBe('pack_not_enabled');
    await expect(
      service.taskDenyReason('t1', { packId: 'coding-agents' }),
    ).resolves.toBe('pack_not_enabled');
  });

  it('turns every pack off with the packs feature, even an enabled pack', async () => {
    const { service } = make({
      row: row({
        features: { packs: false },
        packs: [{ id: 'it-helpdesk', version: 1, enabled: true }],
      }),
    });
    await expect(
      service.taskDenyReason('t1', { packId: 'it-helpdesk' }),
    ).resolves.toBe('packs_disabled');
  });

  it('turns the watcher connector off with the watcher feature, and nothing else', async () => {
    const { service } = make({ row: row({ features: { watcher: false } }) });
    await expect(service.taskDenyReason('t1', {}, MANAR_TOOL)).resolves.toBe(
      'watcher_disabled',
    );
    await expect(service.taskDenyReason('t1', {}, 'graph')).resolves.toBe(null);
  });

  it('fails closed when the catalog cannot be read', async () => {
    const { service } = make({ rowError: true });
    await expect(
      service.taskDenyReason('t1', { packId: 'it-helpdesk' }),
    ).rejects.toThrow('control db down');
    await expect(
      service.taskDenyReason('t1', {}, MANAR_TOOL),
    ).rejects.toThrow();
  });

  it('fails closed on a stored row that does not parse', async () => {
    const { service } = make({
      row: row({ features: { watcher: 'yes' } }),
    });
    await expect(service.taskDenyReason('t1', {}, MANAR_TOOL)).rejects.toThrow(
      'malformed',
    );
  });
});

describe('CatalogService.llmGate (LLM proxy and assistant)', () => {
  it('uses the deployment model for an unmanaged tenant', async () => {
    const { service } = make();
    await expect(service.llmGate('t1', 'llm_proxy')).resolves.toEqual({
      route: null,
    });
  });

  it('refuses a surface staff switched off', async () => {
    const { service } = make({
      row: row({ features: { llm_proxy: false, assistant: false } }),
    });
    await expect(service.llmGate('t1', 'llm_proxy')).rejects.toEqual(
      new CatalogDenied('llm_proxy_disabled'),
    );
    await expect(service.llmGate('t1', 'assistant')).rejects.toEqual(
      new CatalogDenied('assistant_disabled'),
    );
  });

  it('refuses an external model when the tenant does not allow external AI', async () => {
    const { service } = make({ row: row({ model: azure }) });
    await expect(service.llmGate('t1', 'llm_proxy')).rejects.toEqual(
      new CatalogDenied('llm_external_not_allowed'),
    );
  });

  it('refuses a model not declared UAE-resident for a UAE tenant', async () => {
    const { service } = make({
      row: row({
        model: {
          provider: 'ollama',
          model: 'qwen3.5:9b',
          uaeResidency: false,
          monthlyTokenQuota: null,
        },
      }),
    });
    await expect(service.llmGate('t1', 'llm_proxy')).rejects.toEqual(
      new CatalogDenied('llm_residency_mismatch'),
    );
  });

  it('routes to the tenant model when the rules hold', async () => {
    const { service } = make({
      row: row({ model: azure }),
      tenant: { residency: 'UAE', allowExternalAi: true },
    });
    await expect(service.llmGate('t1', 'assistant')).resolves.toEqual({
      route: { provider: 'azure_openai', model: 'gpt-5-mini' },
    });
  });

  it('refuses once the monthly token quota is used, and fails closed if usage is unreadable', async () => {
    const model = { ...azure, monthlyTokenQuota: 1000 };
    const tenant = { residency: 'UAE', allowExternalAi: true };
    await expect(
      make({ row: row({ model }), tenant, used: 1000 }).service.llmGate(
        't1',
        'llm_proxy',
      ),
    ).rejects.toEqual(new CatalogDenied('llm_token_quota_exhausted'));
    await expect(
      make({ row: row({ model }), tenant, used: 999 }).service.llmGate(
        't1',
        'llm_proxy',
      ),
    ).resolves.toEqual({
      route: { provider: 'azure_openai', model: 'gpt-5-mini' },
    });
    await expect(
      make({ row: row({ model }), tenant, usageError: true }).service.llmGate(
        't1',
        'llm_proxy',
      ),
    ).rejects.toThrow('redis down');
  });
});

describe('catalogGate', () => {
  it('turns a catalog refusal into 403 DENY and a store failure into 503', async () => {
    await expect(
      catalogGate(() => Promise.reject(new CatalogDenied('pack_not_enabled'))),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      catalogGate(() => Promise.reject(new Error('down'))),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});

describe('CatalogService.update', () => {
  it('merges features key by key, upserts packs by id and audits in the tenant chain', async () => {
    const { service, upsert, recordSafely } = make({
      row: row({
        features: { watcher: false },
        packs: [{ id: 'it-helpdesk', version: 1, enabled: true }],
      }),
    });
    await service.update(
      't1',
      CatalogPatchSchema.parse({
        features: { assistant: false },
        packs: [
          { id: 'it-helpdesk', version: 2, enabled: true },
          { id: 'coding-agents', version: 1, enabled: true },
        ],
      }),
      'manar-fleet',
    );
    const data = upsert.mock.calls[0]![0].update;
    expect(data.features).toEqual({ assistant: false, watcher: false });
    expect(data.packs).toEqual([
      { id: 'it-helpdesk', version: 2, enabled: true },
      { id: 'coding-agents', version: 1, enabled: true },
    ]);
    expect(data.updatedBy).toBe('manar-fleet');
    expect(recordSafely).toHaveBeenCalledOnce();
  });

  it('stores only what staff set for a first write, so later defaults still apply', async () => {
    const { service, upsert } = make();
    await service.update(
      't1',
      CatalogPatchSchema.parse({ features: { watcher: false } }),
      'manar-fleet',
    );
    expect(upsert.mock.calls[0]![0].create.features).toEqual({
      watcher: false,
    });
  });

  it('rejects an empty or unknown change', () => {
    expect(CatalogPatchSchema.safeParse({}).success).toBe(false);
    expect(
      CatalogPatchSchema.safeParse({ features: { billing: true } }).success,
    ).toBe(false);
    expect(
      CatalogPatchSchema.safeParse({
        model: { ...azure, provider: 'openai' },
      }).success,
    ).toBe(false);
  });
});
