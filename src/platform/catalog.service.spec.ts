import {
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { MANAR_TOOL } from '../tools/manar-actions';
import { CatalogDenied, CatalogService, catalogGate } from './catalog.service';
import { CatalogPatchSchema, StoredCatalogSchema } from './catalog.validation';

type Row = {
  features: unknown;
  packs: unknown;
  model: unknown;
  updatedBy: string;
  updatedAt: Date;
} | null;

const AGENT = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';

function make(
  opts: {
    row?: Row;
    rowError?: boolean;
    tenant?: { residency: string; allowExternalAi: boolean; status?: string };
    used?: number;
    usageError?: boolean;
    env?: Record<string, string>;
    auditFails?: boolean;
  } = {},
) {
  const tenant = {
    id: 't1',
    status: 'ACTIVE',
    residency: 'UAE',
    allowExternalAi: false,
    ...opts.tenant,
  };
  const stored = opts.row ?? null;
  const writes: Record<string, unknown>[] = [];
  const sql: string[] = [];
  const tx = {
    $executeRaw: vi.fn((s: TemplateStringsArray) => {
      sql.push(s.join('?'));
      return Promise.resolve(1);
    }),
    $queryRaw: vi.fn((s: TemplateStringsArray) => {
      sql.push(s.join('?'));
      return Promise.resolve([
        stored ?? { features: {}, packs: [], model: null },
      ]);
    }),
    tenantCatalog: {
      update: vi.fn((a: { data: Record<string, unknown> }) => {
        writes.push(a.data);
        return Promise.resolve({});
      }),
    },
  };
  let committed = false;
  const control = {
    tenantCatalog: {
      findUnique: opts.rowError
        ? vi.fn().mockRejectedValue(new Error('control db down'))
        : vi.fn().mockResolvedValue(stored),
    },
    tenant: {
      findUnique: vi.fn().mockResolvedValue(tenant),
      findUniqueOrThrow: vi.fn().mockResolvedValue(tenant),
    },
    $transaction: async (fn: (t: typeof tx) => Promise<unknown>) => {
      const r = await fn(tx);
      committed = true;
      return r;
    },
  };
  const usage = {
    used: opts.usageError
      ? vi.fn().mockRejectedValue(new Error('redis down'))
      : vi.fn().mockResolvedValue(opts.used ?? 0),
    add: vi.fn().mockResolvedValue(1),
  };
  const record = opts.auditFails
    ? vi.fn().mockRejectedValue(new Error('audit down'))
    : vi.fn().mockResolvedValue({});
  const db = {
    tool: { findMany: vi.fn().mockResolvedValue([]) },
    agent: { findMany: vi.fn().mockResolvedValue([]) },
  };
  const env: Record<string, string> = { LLM_PROVIDER: 'ollama', ...opts.env };
  const service = new CatalogService(
    control as never,
    usage as never,
    { record } as never,
    { getClient: vi.fn().mockResolvedValue(db) } as never,
    { get: (k: string) => env[k] } as never,
  );
  return { service, writes, sql, record, committed: () => committed };
}

const row = (r: Partial<NonNullable<Row>>): Row => ({
  features: {},
  packs: [],
  model: null,
  updatedBy: 'manar-fleet',
  updatedAt: new Date(),
  ...r,
});
const pack = (id: string, enabled: boolean, agents: string[] = []) => ({
  id,
  version: 1,
  enabled,
  agents,
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
    await expect(
      service.taskDenyReason('t1', { assignedAgentId: AGENT }, 'graph'),
    ).resolves.toBe(null);
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
        packs: [pack('it-helpdesk', true), pack('hr-joiner-leaver', false)],
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

  it("stops a bound agent's task without a packId when its pack is disabled", async () => {
    const { service } = make({
      row: row({ packs: [pack('it-helpdesk', false, [AGENT])] }),
    });
    await expect(
      service.taskDenyReason('t1', { assignedAgentId: AGENT }, 'graph'),
    ).resolves.toBe('pack_not_enabled');
    await expect(
      service.taskDenyReason('t1', { assignedAgentId: OTHER }, 'graph'),
    ).resolves.toBe(null);
  });

  it("refuses a task that names another pack than its agent's", async () => {
    const { service } = make({
      row: row({
        packs: [
          pack('it-helpdesk', true, [AGENT]),
          pack('coding-agents', true),
        ],
      }),
    });
    await expect(
      service.taskDenyReason('t1', {
        packId: 'coding-agents',
        assignedAgentId: AGENT,
      }),
    ).resolves.toBe('pack_mismatch');
  });

  it('turns every pack off with the packs feature, even an enabled pack', async () => {
    const { service } = make({
      row: row({
        features: { packs: false },
        packs: [pack('it-helpdesk', true)],
      }),
    });
    await expect(
      service.taskDenyReason('t1', { packId: 'it-helpdesk' }),
    ).resolves.toBe('packs_disabled');
  });

  it('turns the watcher connector off with the watcher feature, and hides it from manifests', async () => {
    const { service } = make({ row: row({ features: { watcher: false } }) });
    await expect(service.taskDenyReason('t1', {}, MANAR_TOOL)).resolves.toBe(
      'watcher_disabled',
    );
    await expect(service.taskDenyReason('t1', {}, 'graph')).resolves.toBe(null);
    await expect(service.hiddenTools('t1')).resolves.toEqual([MANAR_TOOL]);
    await expect(make().service.hiddenTools('t1')).resolves.toEqual([]);
  });

  it('fails closed when the catalog cannot be read, for every task', async () => {
    const { service } = make({ rowError: true });
    await expect(
      service.taskDenyReason('t1', { assignedAgentId: AGENT }, 'graph'),
    ).rejects.toThrow('control db down');
    await expect(
      service.taskDenyReason('t1', {}, MANAR_TOOL),
    ).rejects.toThrow();
  });

  it('fails closed on a stored row that does not parse', async () => {
    const { service } = make({ row: row({ features: { watcher: 'yes' } }) });
    await expect(service.taskDenyReason('t1', {}, MANAR_TOOL)).rejects.toThrow(
      'malformed',
    );
  });
});

describe('CatalogService.resolveTaskPack (task creation)', () => {
  const bound = row({
    packs: [pack('it-helpdesk', true, [AGENT]), pack('coding-agents', true)],
  });

  it("gives a bound agent's task its pack, and refuses another one", async () => {
    const { service } = make({ row: bound });
    await expect(service.resolveTaskPack('t1', AGENT)).resolves.toBe(
      'it-helpdesk',
    );
    await expect(
      service.resolveTaskPack('t1', AGENT, 'coding-agents'),
    ).rejects.toEqual(new CatalogDenied('pack_mismatch'));
    await expect(service.resolveTaskPack('t1', OTHER)).resolves.toBe(null);
    await expect(
      service.resolveTaskPack('t1', OTHER, 'coding-agents'),
    ).resolves.toBe('coding-agents');
  });

  it('refuses a pack that is not enabled', async () => {
    const { service } = make();
    await expect(
      service.resolveTaskPack('t1', OTHER, 'it-helpdesk'),
    ).rejects.toEqual(new CatalogDenied('pack_not_enabled'));
  });
});

describe('CatalogService.llmGate (LLM proxy and assistant)', () => {
  it('uses the local default model for an unmanaged UAE tenant', async () => {
    const { service } = make();
    await expect(service.llmGate('t1', 'llm_proxy')).resolves.toEqual({
      route: null,
      quota: null,
    });
  });

  it('externalAiSwitchedOff is true only when "Allow external AI" is the sole blocker', async () => {
    const env = { LLM_PROVIDER: 'azure_openai' };
    // Azure OpenAI, workspace has the switch off: switched off.
    await expect(
      make({ env }).service.externalAiSwitchedOff('t1', 'assistant'),
    ).resolves.toBe(true);
    // Switch on: not switched off.
    await expect(
      make({
        env,
        tenant: { residency: 'CUSTOM_REGION', allowExternalAi: true },
      }).service.externalAiSwitchedOff('t1', 'assistant'),
    ).resolves.toBe(false);
    // Another refusal (residency) is not reported as switched off.
    await expect(
      make({
        env,
        tenant: { residency: 'UAE', allowExternalAi: true },
      }).service.externalAiSwitchedOff('t1', 'assistant'),
    ).resolves.toBe(false);
    // A local model is never gated by the switch.
    await expect(
      make().service.externalAiSwitchedOff('t1', 'assistant'),
    ).resolves.toBe(false);
  });

  it('an air-gapped workspace is refused every external model, even with allowExternalAi on; a local model is fine', async () => {
    const tenant = { residency: 'AIR_GAPPED', allowExternalAi: true };
    await expect(
      make({ env: { LLM_PROVIDER: 'azure_openai' }, tenant }).service.llmGate(
        't1',
        'assistant',
      ),
    ).rejects.toEqual(new CatalogDenied('llm_air_gapped'));
    await expect(
      make({ tenant }).service.llmGate('t1', 'assistant'),
    ).resolves.toEqual({ route: null, quota: null });
  });

  it('applies the external-AI and residency rules to the deployment default too', async () => {
    const env = { LLM_PROVIDER: 'azure_openai' };
    await expect(
      make({ env }).service.llmGate('t1', 'llm_proxy'),
    ).rejects.toEqual(new CatalogDenied('llm_external_not_allowed'));
    const tenant = { residency: 'UAE', allowExternalAi: true };
    await expect(
      make({ env, tenant }).service.llmGate('t1', 'assistant'),
    ).rejects.toEqual(new CatalogDenied('llm_residency_mismatch'));
    await expect(
      make({
        env: { ...env, LLM_DEFAULT_UAE_RESIDENT: 'true' },
        tenant,
      }).service.llmGate('t1', 'assistant'),
    ).resolves.toEqual({ route: null, quota: null });
  });

  it('judges a fixed upstream (the Anthropic-format proxy) by its own placement, not the catalog model', async () => {
    // Local default model, but the fixed upstream is external and outside the UAE.
    const fixed = { external: true, uaeResident: false, model: 'claude-x' };
    await expect(
      make().service.llmGate('t1', 'llm_proxy', fixed),
    ).rejects.toEqual(new CatalogDenied('llm_external_not_allowed'));
    const tenant = { residency: 'UAE', allowExternalAi: true };
    await expect(
      make({ tenant }).service.llmGate('t1', 'llm_proxy', fixed),
    ).rejects.toEqual(new CatalogDenied('llm_residency_mismatch'));
    await expect(
      make({ tenant }).service.llmGate('t1', 'llm_proxy', {
        ...fixed,
        uaeResident: true,
      }),
    ).resolves.toEqual({ route: null, quota: null });
  });

  it("refuses the fixed upstream when the tenant's catalog pins another model", async () => {
    const tenant = { residency: 'CUSTOM_REGION', allowExternalAi: true };
    const pinned = (model: string) =>
      make({
        tenant,
        row: row({
          model: {
            provider: 'azure_openai',
            model,
            uaeResidency: false,
            monthlyTokenQuota: null,
          },
        }),
      }).service;
    const fixed = { external: true, uaeResident: false, model: 'claude-x' };
    await expect(
      pinned('gpt-5-mini').llmGate('t1', 'llm_proxy', fixed),
    ).rejects.toEqual(new CatalogDenied('llm_model_not_allowed'));
    await expect(
      pinned('claude-x').llmGate('t1', 'llm_proxy', fixed),
    ).resolves.toMatchObject({
      quota: null,
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

  it("refuses the tenant's external model when the tenant does not allow external AI", async () => {
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
      quota: null,
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
      quota: 1000,
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
  it('reads under the row lock, merges, keeps agent bindings and audits inside the transaction', async () => {
    const { service, writes, sql, record } = make({
      row: row({
        features: { watcher: false },
        packs: [pack('it-helpdesk', true, [AGENT])],
      }),
    });
    await service.update(
      't1',
      CatalogPatchSchema.parse({
        features: { assistant: false },
        packs: [
          { id: 'it-helpdesk', version: 2, enabled: true },
          { id: 'coding-agents', version: 1, enabled: true, agents: [OTHER] },
        ],
      }),
      'manar-fleet',
    );
    expect(sql.some((q) => q.includes('INSERT INTO "tenant_catalogs"'))).toBe(
      true,
    );
    expect(sql.some((q) => q.includes('FOR UPDATE'))).toBe(true);
    expect(writes[0]).toMatchObject({
      features: { assistant: false, watcher: false },
      packs: [
        { id: 'it-helpdesk', version: 2, enabled: true, agents: [AGENT] },
        { id: 'coding-agents', version: 1, enabled: true, agents: [OTHER] },
      ],
      updatedBy: 'manar-fleet',
    });
    expect(record).toHaveBeenCalledOnce();
  });

  it('refuses a change whose precondition no longer holds, and writes nothing', async () => {
    const { service, writes, committed } = make({
      row: row({ packs: [pack('it-helpdesk', false)] }),
    });
    await expect(
      service.update(
        't1',
        CatalogPatchSchema.parse({
          packs: [
            {
              id: 'it-helpdesk',
              version: 2,
              enabled: true,
              expect: { enabled: true, maxVersion: 1 },
            },
          ],
        }),
        'manar-fleet',
      ),
    ).rejects.toMatchObject({
      status: 409,
      response: { reason: 'catalog_precondition_failed', pack: 'it-helpdesk' },
    });
    expect(writes).toEqual([]);
    expect(committed()).toBe(false);
  });

  it('never moves a pack back to an older version when maxVersion is set', async () => {
    const { service, writes } = make({
      row: row({ packs: [{ ...pack('it-helpdesk', true), version: 3 }] }),
    });
    await expect(
      service.update(
        't1',
        CatalogPatchSchema.parse({
          packs: [
            {
              id: 'it-helpdesk',
              version: 2,
              enabled: true,
              expect: { maxVersion: 2 },
            },
          ],
        }),
        'manar-fleet',
      ),
    ).rejects.toMatchObject({ status: 409 });
    expect(writes).toEqual([]);
  });

  it('counts a pack not yet in the catalog as disabled at version 0', async () => {
    const { service, writes } = make();
    await expect(
      service.update(
        't1',
        CatalogPatchSchema.parse({
          packs: [
            {
              id: 'it-helpdesk',
              version: 1,
              enabled: true,
              expect: { enabled: true },
            },
          ],
        }),
        'manar-fleet',
      ),
    ).rejects.toMatchObject({ status: 409 });
    await service.update(
      't1',
      CatalogPatchSchema.parse({
        packs: [
          {
            id: 'it-helpdesk',
            version: 1,
            enabled: true,
            expect: { enabled: false, maxVersion: 0 },
          },
        ],
      }),
      'manar-fleet',
    );
    expect(writes[0]!.packs).toEqual([
      { id: 'it-helpdesk', version: 1, enabled: true, agents: [] },
    ]);
  });

  it('a disable never lowers the version a newer publish set', async () => {
    const { service, writes } = make({
      row: row({ packs: [{ ...pack('it-helpdesk', true), version: 2 }] }),
    });
    await service.update(
      't1',
      CatalogPatchSchema.parse({
        packs: [{ id: 'it-helpdesk', version: 1, enabled: false }],
      }),
      'manar-fleet',
    );
    expect(writes[0]!.packs).toEqual([
      { id: 'it-helpdesk', version: 2, enabled: false, agents: [] },
    ]);
  });

  it('stores the pack without its precondition when it holds', async () => {
    const { service, writes } = make({
      row: row({ packs: [pack('it-helpdesk', true)] }),
    });
    await service.update(
      't1',
      CatalogPatchSchema.parse({
        packs: [
          {
            id: 'it-helpdesk',
            version: 2,
            enabled: true,
            expect: { enabled: true, maxVersion: 1 },
          },
        ],
      }),
      'manar-fleet',
    );
    expect(writes[0]!.packs).toEqual([
      { id: 'it-helpdesk', version: 2, enabled: true, agents: [] },
    ]);
  });

  it('changes nothing when the tenant audit event cannot be written', async () => {
    const { service, committed } = make({ auditFails: true });
    await expect(
      service.update(
        't1',
        CatalogPatchSchema.parse({ features: { watcher: false } }),
        'manar-fleet',
      ),
    ).rejects.toThrow('audit down');
    expect(committed()).toBe(false);
  });

  it('stores only what staff set for a first write, so later defaults still apply', async () => {
    const { service, writes } = make();
    await service.update(
      't1',
      CatalogPatchSchema.parse({ features: { watcher: false } }),
      'manar-fleet',
    );
    expect(writes[0]!.features).toEqual({ watcher: false });
  });

  it('rejects an empty or unknown change, duplicate packs and an agent in two packs', () => {
    expect(CatalogPatchSchema.safeParse({}).success).toBe(false);
    expect(
      CatalogPatchSchema.safeParse({ features: { billing: true } }).success,
    ).toBe(false);
    expect(
      CatalogPatchSchema.safeParse({
        model: { ...azure, provider: 'openai' },
      }).success,
    ).toBe(false);
    expect(
      CatalogPatchSchema.safeParse({
        packs: [pack('it-helpdesk', true), pack('it-helpdesk', false)],
      }).success,
    ).toBe(false);
    expect(
      StoredCatalogSchema.safeParse({
        features: {},
        packs: [
          pack('it-helpdesk', true, [AGENT]),
          pack('coding-agents', true, [AGENT]),
        ],
        model: null,
      }).success,
    ).toBe(false);
  });
});
