import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { failClosed } from '../common/fail-closed/fail-closed';
import { ConfigService } from '@nestjs/config';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { Prisma } from '../generated/control-client/client';
import type { AppConfig } from '../config/env.validation';
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
  /** Tokens left this month under the tenant's quota; null = no quota. */
  quota: number | null;
}

type Pack = StoredCatalog['packs'][number];

/**
 * Per-tenant catalog: feature flags, enabled packs (and the agents bound to each), and the LLM
 * route, set by Manar staff through manar-fleet. Enforced here and nowhere else:
 *
 * - `taskDenyReason`: the decision path and the agent-runtime gate (watcher connector, packs).
 *   A task's pack is its own `packId`, or the pack its agent is bound to; disabling the pack
 *   stops both.
 * - `resolveTaskPack`: task creation (a bound agent's task gets its pack; a different one is refused).
 * - `llmGate` / `recordTokens`: the LLM proxy and the console assistant (flag, external-AI and
 *   residency rules on the model actually used, monthly token quota).
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
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  private parse(
    tenantId: string,
    row: { features: unknown; packs: unknown; model: unknown },
  ): StoredCatalog {
    const parsed = StoredCatalogSchema.safeParse({
      features: row.features,
      packs: row.packs,
      model: row.model,
    });
    if (!parsed.success)
      throw new Error(`tenant catalog row for ${tenantId} is malformed`);
    return parsed.data;
  }

  async state(tenantId: string): Promise<CatalogState> {
    const row = await this.control.tenantCatalog.findUnique({
      where: { tenantId },
    });
    const s = row ? this.parse(tenantId, row) : null;
    return {
      managed: row !== null,
      features: { ...FEATURE_DEFAULTS, ...s?.features },
      packs: s?.packs ?? [],
      model: s?.model ?? null,
      updatedBy: row?.updatedBy ?? null,
      updatedAt: row?.updatedAt ?? null,
    };
  }

  /** The task's pack: its own, or its agent's. Refuses a task bound to another pack than its agent. */
  private taskPack(
    s: CatalogState,
    task: { packId?: string | null; assignedAgentId?: string },
  ): { pack: string | null; mismatch: boolean } {
    const bound = task.assignedAgentId
      ? s.packs.find((p) => p.agents.includes(task.assignedAgentId!))
      : undefined;
    if (task.packId && bound && bound.id !== task.packId)
      return { pack: task.packId, mismatch: true };
    return { pack: task.packId ?? bound?.id ?? null, mismatch: false };
  }

  private packDeny(s: CatalogState, pack: string): string | null {
    if (!s.features.packs) return 'packs_disabled';
    if (!s.packs.some((p) => p.id === pack && p.enabled))
      return 'pack_not_enabled';
    return null;
  }

  /**
   * Null when the catalog lets this task act, else the DENY reason. The watcher's built-in
   * connector needs `watcher`; a pack task (own `packId` or a bound agent) needs `packs` and its
   * pack enabled. Throws (never allows) when the catalog cannot be read.
   */
  async taskDenyReason(
    tenantId: string,
    task: { packId?: string | null; assignedAgentId?: string },
    toolId?: string,
  ): Promise<string | null> {
    const s = await this.state(tenantId);
    if (toolId === MANAR_TOOL && !s.features.watcher) return 'watcher_disabled';
    const { pack, mismatch } = this.taskPack(s, task);
    if (mismatch) return 'pack_mismatch';
    return pack ? this.packDeny(s, pack) : null;
  }

  /**
   * The pack a new task belongs to: the one requested or the one its agent is bound to. Throws
   * `CatalogDenied` for a mismatch or a pack that is not enabled.
   */
  async resolveTaskPack(
    tenantId: string,
    assignedAgentId: string,
    requested?: string,
  ): Promise<string | null> {
    const s = await this.state(tenantId);
    const { pack, mismatch } = this.taskPack(s, {
      packId: requested,
      assignedAgentId,
    });
    if (mismatch) throw new CatalogDenied('pack_mismatch');
    const deny = pack ? this.packDeny(s, pack) : null;
    if (deny) throw new CatalogDenied(deny);
    return pack;
  }

  /** Tools the tenant's agents must not even see listed (the watcher's connector when it is off). */
  async hiddenTools(tenantId: string): Promise<string[]> {
    const s = await this.state(tenantId);
    return s.features.watcher ? [] : [MANAR_TOOL];
  }

  /**
   * Before any model call. Throws `CatalogDenied` when the surface is off, the model actually used
   * (the tenant's, or the deployment default) sends prompts outside the deployment while the
   * tenant does not allow external AI, that model is not UAE-resident for a UAE tenant, or the
   * month's token quota is used up.
   */
  async llmGate(
    tenantId: string,
    surface: 'llm_proxy' | 'assistant',
    /** A fixed upstream outside the catalog's providers (the Anthropic-format proxy's own). */
    fixed?: { external: boolean; uaeResident: boolean },
  ): Promise<LlmRoute> {
    const s = await this.state(tenantId);
    if (!s.features[surface]) throw new CatalogDenied(`${surface}_disabled`);
    const provider: LlmProvider =
      s.model?.provider ??
      this.config.get('LLM_PROVIDER', { infer: true }) ??
      'ollama';
    // Ollama runs inside the deployment, so it is as resident as the deployment itself.
    const uaeResident = fixed
      ? fixed.uaeResident
      : s.model
        ? s.model.uaeResidency
        : provider === 'ollama' ||
          this.config.get('LLM_DEFAULT_UAE_RESIDENT', { infer: true }) ===
            'true';
    const external = fixed
      ? fixed.external
      : EXTERNAL_PROVIDERS.includes(provider);
    const tenant = await this.control.tenant.findUniqueOrThrow({
      where: { id: tenantId },
      select: { residency: true, allowExternalAi: true },
    });
    if (external && !tenant.allowExternalAi)
      throw new CatalogDenied('llm_external_not_allowed');
    if (tenant.residency === 'UAE' && !uaeResident)
      throw new CatalogDenied('llm_residency_mismatch');
    let quota: number | null = null;
    if (s.model && s.model.monthlyTokenQuota !== null) {
      quota = s.model.monthlyTokenQuota;
      const used = await this.usage.used(tenantId);
      if (used >= quota) throw new CatalogDenied('llm_token_quota_exhausted');
    }
    return {
      route: s.model ? { provider, model: s.model.model } : null,
      quota,
    };
  }

  recordTokens(tenantId: string, tokens: number): Promise<number> {
    return this.usage.add(tenantId, tokens);
  }

  /** The platform API's view: stored state, this month's model tokens, tools and agents. */
  async view(tenantId: string) {
    const t = await this.tenantOr404(tenantId);
    const s = await this.state(tenantId);
    const month = usageMonth();
    let tokens: number | null = null;
    try {
      tokens = await this.usage.used(tenantId, month);
    } catch {
      // Reporting only: an unreadable counter is shown as unknown, never as zero.
    }
    const live = t.status === 'ACTIVE' ? await this.inventory(tenantId) : null;
    return {
      tenantId,
      ...s,
      usage: { month, tokens },
      connectors: live?.tools ?? null,
      agents: live?.agents ?? null,
    };
  }

  /**
   * Registered tools (names and kind only; credential expiry is on the ops route, from OpenBao
   * metadata) and agents (for binding them to a pack). Never credentials or references.
   */
  private async inventory(tenantId: string) {
    const db = await this.tenants.getClient(tenantId);
    const [tools, agents] = await Promise.all([
      db.tool.findMany({
        select: {
          name: true,
          type: true,
          vendor: true,
          protocol: true,
          enabled: true,
        },
        orderBy: { name: 'asc' },
      }),
      db.agent.findMany({
        select: { id: true, slug: true, displayName: true, status: true },
        orderBy: { displayName: 'asc' },
        take: 500,
      }),
    ]);
    return { tools, agents };
  }

  /**
   * Applies a staff change: read, merge and write the row in one control-DB transaction holding
   * the row lock, so two approved changes for the same tenant never undo each other. The tenant
   * audit event is written inside that transaction: no event, no change.
   */
  async update(tenantId: string, patch: CatalogPatch, caller: string) {
    const tenant = await this.tenantOr404(tenantId);
    const db =
      tenant.status === 'ACTIVE'
        ? await this.tenants.getClient(tenantId)
        : null;
    await this.control.$transaction(async (tx) => {
      await tx.$executeRaw`
        INSERT INTO "tenant_catalogs" ("tenantId", "updatedBy", "updatedAt")
        VALUES (${tenantId}, ${caller}, now())
        ON CONFLICT ("tenantId") DO NOTHING`;
      const [row] = await tx.$queryRaw<
        { features: unknown; packs: unknown; model: unknown }[]
      >`SELECT "features", "packs", "model" FROM "tenant_catalogs"
        WHERE "tenantId" = ${tenantId} FOR UPDATE`;
      const before = this.parse(tenantId, row!);
      const packs: Pack[] = [...before.packs];
      for (const { expect, ...p } of patch.packs ?? []) {
        const i = packs.findIndex((x) => x.id === p.id);
        const current = i >= 0 ? packs[i]! : { enabled: false, version: 0 };
        if (
          (expect?.enabled !== undefined &&
            current.enabled !== expect.enabled) ||
          (expect?.maxVersion !== undefined &&
            current.version > expect.maxVersion)
        )
          throw new ConflictException({
            reason: 'catalog_precondition_failed',
            pack: p.id,
            current: { enabled: current.enabled, version: current.version },
          });
        const agents = p.agents ?? (i >= 0 ? packs[i]!.agents : []);
        // Disabling never lowers the version: a disable proposed before a publish keeps the newer one.
        const version = p.enabled
          ? p.version
          : Math.max(current.version, p.version);
        if (i >= 0) packs[i] = { ...p, version, agents };
        else packs.push({ ...p, version, agents });
      }
      // Only keys staff set are stored, so an unset feature keeps following its default.
      const next = StoredCatalogSchema.parse({
        features: { ...before.features, ...patch.features },
        packs,
        model: patch.model === undefined ? before.model : patch.model,
      });
      await tx.tenantCatalog.update({
        where: { tenantId },
        data: {
          features: next.features,
          packs: next.packs,
          model: next.model ?? Prisma.DbNull,
          updatedBy: caller,
        },
      });
      if (db)
        await this.audit.record(db, tenantId, {
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
    });
    this.logger.log(
      `platform: catalog of tenant ${tenantId} updated by ${caller} (${Object.keys(patch).join(', ')})`,
    );
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
