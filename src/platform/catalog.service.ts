import {
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { failClosed } from '../common/fail-closed/fail-closed';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { Prisma } from '../generated/control-client/client';
import { MANAR_TOOL } from '../tools/manar-actions';
import { CatalogUsageStore, usageMonth } from './catalog.usage';
import {
  EXTERNAL_PROVIDERS,
  FEATURE_DEFAULTS,
  StoredCatalogSchema,
  type CatalogFeature,
  type CatalogPatch,
  type LlmProvider,
  type ModelConfig,
  type StoredCatalog,
} from './catalog.validation';

export interface CatalogState {
  /** False when staff have never set anything for this tenant (no row). */
  managed: boolean;
  features: Record<CatalogFeature, boolean>;
  packs: StoredCatalog['packs'];
  model: ModelConfig | null;
  updatedBy: string | null;
  updatedAt: Date | null;
}

/** A refusal with a stable reason code; callers turn it into their own 403 shape. */
export class CatalogDenied extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = 'CatalogDenied';
  }
}

/**
 * Runs a catalog check for a request handler: `CatalogDenied` becomes 403
 * `{ decision: 'DENY', reason }`, any other failure 503 `enforcement_dependency_unavailable`.
 */
export function catalogGate<T>(fn: () => Promise<T>): Promise<T> {
  return failClosed('catalog-store', async () => {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof CatalogDenied)
        throw new ForbiddenException({
          decision: 'DENY',
          reason: error.reason,
        });
      throw error;
    }
  });
}

export interface LlmRoute {
  /** Null: the deployment's own LLM_PROVIDER and model. */
  route: { provider: LlmProvider; model: string } | null;
}

/**
 * Per-tenant catalog: feature flags, enabled packs and the LLM route, set by Manar staff through
 * manar-fleet. Enforced here and nowhere else:
 *
 * - `taskDenyReason`: the decision path and the agent-runtime gate (watcher connector, packs).
 * - `llmGate` / `recordTokens`: the LLM proxy and the console assistant (flag, external-AI and
 *   residency rules, monthly token quota).
 *
 * Every read is PostgreSQL (control DB) or Redis. A failed read or a stored row that does not
 * parse throws a plain error, which every caller turns into a DENY or 503
 * `enforcement_dependency_unavailable`: a disabled feature stays off when the store is down.
 */
@Injectable()
export class CatalogService {
  private readonly logger = new Logger(CatalogService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly usage: CatalogUsageStore,
    private readonly audit: AuditService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  /** The stored row, parsed; null when there is none. Throws on a read failure or a bad row. */
  private async stored(tenantId: string) {
    const row = await this.control.tenantCatalog.findUnique({
      where: { tenantId },
    });
    if (!row) return null;
    const parsed = StoredCatalogSchema.safeParse({
      features: row.features,
      packs: row.packs,
      model: row.model,
    });
    if (!parsed.success)
      throw new Error(`tenant catalog row for ${tenantId} is malformed`);
    return {
      ...parsed.data,
      updatedBy: row.updatedBy,
      updatedAt: row.updatedAt,
    };
  }

  async state(tenantId: string): Promise<CatalogState> {
    const row = await this.stored(tenantId);
    return {
      managed: row !== null,
      features: { ...FEATURE_DEFAULTS, ...row?.features },
      packs: row?.packs ?? [],
      model: row?.model ?? null,
      updatedBy: row?.updatedBy ?? null,
      updatedAt: row?.updatedAt ?? null,
    };
  }

  /**
   * Null when the catalog lets this task act, else the DENY reason. The watcher's built-in
   * connector needs `watcher`; a pack-bound task needs `packs` and its own pack enabled. Throws
   * (never allows) when the catalog cannot be read.
   */
  async taskDenyReason(
    tenantId: string,
    task: { packId?: string | null },
    toolId?: string,
  ): Promise<string | null> {
    if (toolId !== MANAR_TOOL && !task.packId) return null;
    const s = await this.state(tenantId);
    if (toolId === MANAR_TOOL && !s.features.watcher) return 'watcher_disabled';
    if (task.packId) {
      if (!s.features.packs) return 'packs_disabled';
      if (!s.packs.some((p) => p.id === task.packId && p.enabled))
        return 'pack_not_enabled';
    }
    return null;
  }

  /**
   * Before any model call. Throws `CatalogDenied` when the surface is off, the tenant's model
   * sends prompts outside Manar while the tenant does not allow external AI, the model is not
   * declared UAE-resident for a UAE tenant, or the month's token quota is used up.
   */
  async llmGate(
    tenantId: string,
    surface: 'llm_proxy' | 'assistant',
  ): Promise<LlmRoute> {
    const s = await this.state(tenantId);
    if (!s.features[surface]) throw new CatalogDenied(`${surface}_disabled`);
    if (!s.model) return { route: null };
    const tenant = await this.control.tenant.findUniqueOrThrow({
      where: { id: tenantId },
      select: { residency: true, allowExternalAi: true },
    });
    if (
      EXTERNAL_PROVIDERS.includes(s.model.provider) &&
      !tenant.allowExternalAi
    )
      throw new CatalogDenied('llm_external_not_allowed');
    if (tenant.residency === 'UAE' && !s.model.uaeResidency)
      throw new CatalogDenied('llm_residency_mismatch');
    if (s.model.monthlyTokenQuota !== null) {
      const used = await this.usage.used(tenantId);
      if (used >= s.model.monthlyTokenQuota)
        throw new CatalogDenied('llm_token_quota_exhausted');
    }
    return { route: { provider: s.model.provider, model: s.model.model } };
  }

  recordTokens(tenantId: string, tokens: number): Promise<number> {
    return this.usage.add(tenantId, tokens);
  }

  /** The platform API's view: stored state plus this month's model tokens. */
  async view(tenantId: string) {
    await this.tenantOr404(tenantId);
    const s = await this.state(tenantId);
    const month = usageMonth();
    let tokens: number | null = null;
    try {
      tokens = await this.usage.used(tenantId, month);
    } catch {
      // Reporting only: an unreadable counter is shown as unknown, never as zero.
    }
    return {
      tenantId,
      ...s,
      usage: { month, tokens },
      connectors: await this.connectors(tenantId),
    };
  }

  /**
   * The tenant's registered tools, for the fleet's connector setup view: names, kind and the
   * credential expiry an operator recorded in the tool's metadata (`credentialExpiresAt`, ISO
   * date). Never the credential or its reference. Null while the tenant is not ACTIVE.
   */
  private async connectors(tenantId: string) {
    const t = await this.tenantOr404(tenantId);
    if (t.status !== 'ACTIVE') return null;
    const db = await this.tenants.getClient(tenantId);
    const tools = await db.tool.findMany({
      select: {
        name: true,
        type: true,
        vendor: true,
        protocol: true,
        enabled: true,
        metadata: true,
      },
      orderBy: { name: 'asc' },
    });
    return tools.map(({ metadata, ...tool }) => {
      const raw = (metadata as Record<string, unknown> | null)
        ?.credentialExpiresAt;
      const expiry = typeof raw === 'string' ? new Date(raw) : null;
      return {
        ...tool,
        credentialExpiresAt:
          expiry && !Number.isNaN(expiry.getTime()) ? expiry : null,
      };
    });
  }

  /** Merges a staff change into the row; the result must still parse. Audited in the tenant chain. */
  async update(tenantId: string, patch: CatalogPatch, caller: string) {
    const tenant = await this.tenantOr404(tenantId);
    const before = await this.stored(tenantId);
    const packs = [...(before?.packs ?? [])];
    for (const p of patch.packs ?? []) {
      const i = packs.findIndex((x) => x.id === p.id);
      if (i >= 0) packs[i] = p;
      else packs.push(p);
    }
    // Only keys staff set are stored, so an unset feature keeps following its default.
    const next = StoredCatalogSchema.parse({
      features: { ...before?.features, ...patch.features },
      packs,
      model: patch.model === undefined ? (before?.model ?? null) : patch.model,
    });
    const data = {
      features: next.features,
      packs: next.packs,
      model: next.model ?? Prisma.DbNull,
      updatedBy: caller,
    };
    await this.control.tenantCatalog.upsert({
      where: { tenantId },
      create: { tenantId, ...data },
      update: data,
    });
    this.logger.log(
      `platform: catalog of tenant ${tenantId} updated by ${caller} (${Object.keys(patch).join(', ')})`,
    );
    if (tenant.status === 'ACTIVE') {
      const db = await this.tenants.getClient(tenantId);
      await this.audit.recordSafely(db, tenantId, {
        eventType: AUDIT_EVENT_TYPES.CATALOG_UPDATED,
        actor: { type: 'system', id: caller },
        data: {
          features: next.features,
          packs: next.packs,
          model: next.model
            ? {
                provider: next.model.provider,
                model: next.model.model,
                uaeResidency: next.model.uaeResidency,
                monthlyTokenQuota: next.model.monthlyTokenQuota,
              }
            : null,
        },
      });
    }
    return this.view(tenantId);
  }

  private async tenantOr404(id: string) {
    const t = await this.control.tenant.findUnique({
      where: { id },
      select: { id: true, status: true },
    });
    if (!t) throw new NotFoundException('No such tenant');
    return t;
  }
}
