import { X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuditService } from '../audit/audit.service';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import { OpenBaoPkiClient } from '../openbao/openbao-pki.client';
import { PLATFORM_SWITCH_ID } from './platform-suspension';

/** How many calendar months of decision counts the platform API and the heartbeat report. */
export const USAGE_MONTHS = 6;
const QUARANTINE_HISTORY_DAYS = 30;
const MAX_EXPIRIES = 64;

export type ExpiryKind = 'agent_ca' | 'tls_server' | 'tool_credential';

export interface MonthCount {
  month: string;
  decisions: number;
}

export interface AuditChainSummary {
  status: 'ok' | 'broken' | 'unknown';
  tenantsChecked: number;
  tenantsBroken: number;
  verifiedAt: string | null;
}

const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);

/** "YYYY-MM" of the first month in the window, UTC. */
function windowStart(now = new Date()): Date {
  return new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - (USAGE_MONTHS - 1), 1),
  );
}

/**
 * Ops reads for manar-fleet (admin v2): a tenant's kill switches, quarantines, usage and
 * credential expiry dates through the platform API, and the deployment-wide figures the signed
 * heartbeat carries. Reads only; never a secret value (credential expiry comes from KV metadata),
 * never prompt or payload content. Quarantine reasons are the detector's deterministic codes; the
 * watcher's generated explanations are left out.
 */
@Injectable()
export class PlatformOpsService {
  private readonly logger = new Logger(PlatformOpsService.name);
  private auditCache?: { at: number; summary: AuditChainSummary };

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly kv: OpenBaoKvClient,
    private readonly pki: OpenBaoPkiClient,
    private readonly audit: AuditService,
  ) {}

  private async activeTenantClient(id: string): Promise<TenantPrismaClient> {
    const t = await this.control.tenant.findUnique({ where: { id } });
    if (!t) throw new NotFoundException('No such tenant');
    if (t.status !== 'ACTIVE')
      throw new NotFoundException('Tenant is not ACTIVE');
    return this.tenants.getClient(id);
  }

  /** Live security, usage and credential view of one ACTIVE tenant. */
  async tenantOps(id: string) {
    const db = await this.activeTenantClient(id);
    const [
      killSwitches,
      quarantines,
      months,
      agentsEnrolled,
      agentsTotal,
      credentials,
    ] = await Promise.all([
      this.killSwitches(db),
      this.quarantines(db),
      this.decisionMonths(db),
      db.agent.count({ where: { status: 'ACTIVE' } }),
      db.agent.count(),
      this.credentials(db),
    ]);
    return {
      killSwitches,
      quarantines,
      usage: { months, agentsEnrolled, agentsTotal },
      credentials: credentials.map(({ tool, vendor, enabled, expiresAt }) => ({
        tool,
        vendor,
        enabled,
        expiresAt,
      })),
    };
  }

  /** Full chain check of one tenant's audit log. */
  async verifyTenantAudit(id: string) {
    const db = await this.activeTenantClient(id);
    return this.verify(db);
  }

  private async verify(db: TenantPrismaClient) {
    const result = await this.audit.verifyAuditChain(db);
    const state = await db.auditChainState.findUnique({
      where: { id: 'singleton' },
    });
    return {
      valid: result.valid,
      eventCount: state?.eventCount ?? 0,
      brokenAt: result.valid ? null : (result.brokenAt ?? null),
      verifiedAt: new Date().toISOString(),
    };
  }

  private async killSwitches(db: TenantPrismaClient) {
    const rows = await db.killSwitch.findMany({
      where: { active: true },
      include: { activator: { select: { displayName: true } } },
      orderBy: { activatedAt: 'desc' },
      take: 200,
    });
    const ids = (scope: string) =>
      rows
        .filter((r) => r.scope === scope && r.targetId)
        .map((r) => r.targetId!);
    const [agents, groups, tools] = await Promise.all([
      db.agent.findMany({
        where: { id: { in: ids('AGENT') } },
        select: { id: true, displayName: true },
      }),
      db.agentGroup.findMany({
        where: { id: { in: ids('AGENT_GROUP') } },
        select: { id: true, name: true },
      }),
      db.tool.findMany({
        where: { id: { in: ids('TOOL') } },
        select: { id: true, name: true },
      }),
    ]);
    const names = new Map<string, string>([
      ...agents.map((a) => [a.id, a.displayName] as [string, string]),
      ...groups.map((g) => [g.id, g.name] as [string, string]),
      ...tools.map((t) => [t.id, t.name] as [string, string]),
    ]);
    return rows.map((r) => {
      const platform = r.id === PLATFORM_SWITCH_ID;
      return {
        scope: r.scope,
        targetId: platform ? null : r.targetId,
        targetName: r.targetId ? (names.get(r.targetId) ?? null) : null,
        activatedBy: r.activator?.displayName ?? null,
        activatedAt: r.activatedAt.toISOString(),
        platform,
      };
    });
  }

  private async quarantines(db: TenantPrismaClient) {
    const since = new Date(Date.now() - QUARANTINE_HISTORY_DAYS * 86_400_000);
    const rows = await db.agentQuarantine.findMany({
      where: { OR: [{ active: true }, { releasedAt: { gte: since } }] },
      include: { agent: { select: { displayName: true } } },
      orderBy: { quarantinedAt: 'desc' },
      take: 100,
    });
    const [watchers, people] = await Promise.all([
      db.agent.findMany({
        where: { id: { in: rows.map((r) => r.quarantinedByAgentId) } },
        select: { id: true, displayName: true },
      }),
      db.userProfile.findMany({
        where: {
          id: { in: rows.flatMap((r) => (r.releasedBy ? [r.releasedBy] : [])) },
        },
        select: { id: true, displayName: true },
      }),
    ]);
    const name = (
      list: { id: string; displayName: string }[],
      id: string | null,
    ) => (id ? (list.find((x) => x.id === id)?.displayName ?? null) : null);
    return rows.map((r) => ({
      agentId: r.agentId,
      agentName: r.agent.displayName,
      active: r.active,
      reason: r.reason,
      detector: r.detector,
      quarantinedBy: name(watchers, r.quarantinedByAgentId),
      quarantinedAt: r.quarantinedAt.toISOString(),
      releasedBy: name(people, r.releasedBy),
      releasedAt: iso(r.releasedAt),
    }));
  }

  /** Decisions per UTC calendar month over the window, oldest first, months with none included. */
  private async decisionMonths(db: TenantPrismaClient): Promise<MonthCount[]> {
    const start = windowStart();
    const rows = await db.$queryRaw<{ month: string; decisions: number }[]>`
      SELECT to_char(date_trunc('month', "createdAt"), 'YYYY-MM') AS month,
             count(*)::int AS decisions
      FROM "decisions" WHERE "createdAt" >= ${start}
      GROUP BY 1`;
    return Array.from({ length: USAGE_MONTHS }, (_, i) => {
      const d = new Date(
        Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + i, 1),
      );
      const month = d.toISOString().slice(0, 7);
      return {
        month,
        decisions: rows.find((r) => r.month === month)?.decisions ?? 0,
      };
    });
  }

  /**
   * Tools whose credential lives in OpenBao, with the `expires_at` an operator recorded in the
   * KV metadata. Null when none is recorded or it cannot be read: unknown, never "fine".
   */
  private async credentials(db: TenantPrismaClient) {
    const tools = await db.tool.findMany({
      select: {
        name: true,
        vendor: true,
        enabled: true,
        credentialReference: true,
      },
      orderBy: { name: 'asc' },
    });
    return Promise.all(
      tools.map(async (t) => {
        const ref = t.credentialReference as {
          provider?: unknown;
          reference?: unknown;
        } | null;
        let expiresAt: string | null = null;
        if (ref?.provider === 'OPENBAO' && typeof ref.reference === 'string') {
          try {
            const meta = await this.kv.readCustomMetadata(ref.reference);
            const at = meta?.expires_at ? new Date(meta.expires_at) : null;
            expiresAt =
              at && !Number.isNaN(at.getTime()) ? at.toISOString() : null;
          } catch {
            expiresAt = null;
          }
        }
        return {
          tool: t.name,
          vendor: t.vendor,
          enabled: t.enabled,
          expiresAt,
        };
      }),
    );
  }

  // Deployment-wide figures for the signed heartbeat. No tenant ids or names leave here.

  async openbaoSealed(): Promise<boolean | null> {
    try {
      const res = await fetch(
        `${this.config.get('OPENBAO_ADDR', { infer: true })}/v1/sys/seal-status`,
        { signal: AbortSignal.timeout(3000) },
      );
      if (!res.ok) return null;
      const body = (await res.json()) as { sealed?: unknown };
      return typeof body.sealed === 'boolean' ? body.sealed : null;
    } catch {
      return null;
    }
  }

  /** Agent CA chain, the mTLS server certificate and every OpenBao tool credential with a date. */
  async expiries(): Promise<{ kind: ExpiryKind; notAfter: string }[]> {
    const out: { kind: ExpiryKind; notAfter: string }[] = [];
    const certs = (pem: string) =>
      pem.match(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
      ) ?? [];
    const notAfter = (pem: string) =>
      new Date(new X509Certificate(pem).validTo).toISOString();
    try {
      for (const c of certs(await this.pki.getCaChainPem()))
        out.push({ kind: 'agent_ca', notAfter: notAfter(c) });
    } catch {
      // OpenBao down or PKI not mounted: health already reports it.
    }
    try {
      const file = this.config.get('AGENT_MTLS_SERVER_CERT_PATH', {
        infer: true,
      });
      const first = certs(await readFile(file, 'utf8'))[0];
      if (first) out.push({ kind: 'tls_server', notAfter: notAfter(first) });
    } catch {
      // No server certificate on this host (CLI, tests).
    }
    for (const db of await this.activeClients())
      for (const c of await this.credentials(db).catch(() => []))
        if (c.expiresAt)
          out.push({ kind: 'tool_credential', notAfter: c.expiresAt });
    return out
      .sort((a, b) => a.notAfter.localeCompare(b.notAfter))
      .slice(0, MAX_EXPIRIES);
  }

  /** Decisions per month summed over every ACTIVE tenant. */
  async usageMonths(): Promise<MonthCount[]> {
    const per = await Promise.all(
      (await this.activeClients()).map((db) =>
        this.decisionMonths(db).catch(() => null),
      ),
    );
    const known = per.filter((m): m is MonthCount[] => m !== null);
    if (!known.length) return [];
    return known[0]!.map((m, i) => ({
      month: m.month,
      decisions: known.reduce((s, k) => s + (k[i]?.decisions ?? 0), 0),
    }));
  }

  /**
   * Audit chain status across ACTIVE tenants, recomputed at most every
   * FLEET_AUDIT_VERIFY_MINUTES (default 60) because a full check walks every event.
   */
  async auditChain(): Promise<AuditChainSummary> {
    const ttl =
      this.config.get('FLEET_AUDIT_VERIFY_MINUTES', { infer: true }) * 60_000;
    if (this.auditCache && Date.now() - this.auditCache.at < ttl)
      return this.auditCache.summary;
    let checked = 0;
    let broken = 0;
    for (const db of await this.activeClients()) {
      try {
        const r = await this.verify(db);
        checked++;
        if (!r.valid) broken++;
      } catch {
        // Unreadable tenant: not counted as checked.
      }
    }
    const summary: AuditChainSummary = {
      status: broken ? 'broken' : checked ? 'ok' : 'unknown',
      tenantsChecked: checked,
      tenantsBroken: broken,
      verifiedAt: checked ? new Date().toISOString() : null,
    };
    if (broken) this.logger.warn(`Audit chain broken in ${broken} tenant(s)`);
    this.auditCache = { at: Date.now(), summary };
    return summary;
  }

  async killSwitchState(): Promise<{
    active: boolean;
    activatedAt: string | null;
  }> {
    const row = await this.control.platformKillSwitch.findUnique({
      where: { id: 'singleton' },
    });
    return { active: row?.active ?? false, activatedAt: iso(row?.activatedAt) };
  }

  private async activeClients(): Promise<TenantPrismaClient[]> {
    const rows = await this.control.tenant.findMany({
      where: { status: 'ACTIVE' },
      select: { id: true },
      orderBy: { id: 'asc' },
    });
    const clients = await Promise.all(
      rows.map((t) => this.tenants.getClient(t.id).catch(() => null)),
    );
    return clients.filter((c): c is TenantPrismaClient => c !== null);
  }
}
