import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  ALWAYS_GRANT_TTL_MS,
  createAllowGrant,
} from '../approvals/allow-grants';
import { scopeMatches } from '../approvals/rule-scope';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import {
  START_MODE_POLICY_NAME,
  modeForContentHash,
} from '../workspace/start-mode.presets';
import { CEILING_ASK } from '../host-coverage/ask-keys';
import {
  LEARNING_DAYS,
  SUGGEST_AFTER,
  learningCandidate,
  learningWindow,
} from './learning';

export type LearningSwitch = 'on' | 'off';
export interface LearningConfig {
  enabled: boolean;
  days: number;
  /** `default` when nobody chose: on, except Government and sample workspaces. */
  source: 'default' | 'workspace';
}

/** Observations without a usable folder or origin (commands) are counted, never suggested. */
export const UNSCOPED = 'unscoped';

const DAY = 86_400_000;

type Actor = { id: string };

@Injectable()
export class LearningService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly audit: AuditService,
  ) {}

  /** Read on every ask while a device may be learning: a switch to "off" takes effect at once. */
  async config(tenantId: string): Promise<LearningConfig> {
    const t = await this.control.tenant.findUnique({
      where: { id: tenantId },
      select: { kind: true, learningMode: true },
    });
    // Fail closed: an unknown workspace does not learn.
    if (!t) return { enabled: false, days: 0, source: 'default' };
    // Government never learns, whatever is stored: it cannot be switched on.
    if (await this.isGovernment(tenantId))
      return { enabled: false, days: LEARNING_DAYS, source: 'default' };
    if (t.learningMode === 'on' || t.learningMode === 'off')
      return {
        enabled: t.learningMode === 'on',
        days: LEARNING_DAYS,
        source: 'workspace',
      };
    return {
      enabled: t.kind !== 'SAMPLE',
      days: LEARNING_DAYS,
      source: 'default',
    };
  }

  private async isGovernment(tenantId: string): Promise<boolean> {
    const gov = await this.control.enterpriseProfile.findUnique({
      where: { tenantId },
      select: { sector: true },
    });
    return gov?.sector === 'GOVERNMENT';
  }

  /** `default` clears the choice. A Government workspace cannot turn learning on (403). */
  async setWorkspace(
    tenantId: string,
    value: LearningSwitch | 'default',
    actor: Actor,
    client: TenantPrismaClient,
  ): Promise<LearningConfig> {
    if (value === 'on' && (await this.isGovernment(tenantId)))
      throw new ForbiddenException(
        'Learning mode is not available in a Government workspace. Nothing was changed.',
      );
    await this.control.tenant.update({
      where: { id: tenantId },
      data: { learningMode: value === 'default' ? null : value },
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.LEARNING_CHANGED,
      actor: { type: 'human', id: actor.id },
      data: { scope: 'workspace', value },
    });
    return this.config(tenantId);
  }

  /**
   * Called only when an action would have asked. True: serve ALLOW, open no approval, and the
   * caller records the real outcome with `learning: true`. Never throws on "no": any failure
   * is the caller's catch, which keeps asking.
   */
  async serve(
    client: TenantPrismaClient,
    tenantId: string,
    host: { hostId: string },
    request: { toolId: string; actionId: string; resource: string },
    ask: { riskScore: number; askKey: string; policyVersionIds?: string[] },
    now: Date = new Date(),
  ): Promise<boolean> {
    const actionId = request.actionId.toLowerCase();
    const candidate = learningCandidate({
      ...request,
      actionId,
      riskScore: ask.riskScore,
    });
    if (!candidate) return false;
    // Only the two kinds of ask learning may quiet: the risk ceiling, and the "ask" start-mode
    // preset's own rules. Never the strict preset's rules ("outside the project", "new websites")
    // and never a rule an admin wrote.
    if (!(await this.quietable(client, ask))) return false;
    const cfg = await this.config(tenantId);
    if (!cfg.enabled) return false;
    const h = await client.host.findUnique({
      where: { id: host.hostId },
      select: {
        firstApprovedAt: true,
        learningStartedAt: true,
        learningOff: true,
      },
    });
    if (!h || !learningWindow(h, cfg.days, now).active) return false;
    // A site never seen before stays an ask: a person must have approved this origin here before.
    if (
      candidate.needsSeenSite &&
      !(await this.siteSeen(client, host.hostId, candidate.scope!))
    )
      return false;
    const scope = candidate.scope ?? UNSCOPED;
    await client.learningObservation.upsert({
      where: {
        hostId_toolId_actionId_scope_askKey: {
          hostId: host.hostId,
          toolId: request.toolId,
          actionId,
          scope,
          askKey: ask.askKey,
        },
      },
      create: {
        hostId: host.hostId,
        toolId: request.toolId,
        actionId,
        scope,
        askKey: ask.askKey,
        firstSeenAt: now,
        lastSeenAt: now,
      },
      update: { count: { increment: 1 }, lastSeenAt: now },
    });
    return true;
  }

  private async quietable(
    client: TenantPrismaClient,
    ask: { askKey: string; policyVersionIds?: string[] },
  ): Promise<boolean> {
    if (ask.askKey === CEILING_ASK) return true;
    // Every policy that asks must be the "ask" preset: if an admin's rule also asks, that rule
    // is not quiet just because the preset happens to be the one reported.
    const ids = [...new Set(ask.policyVersionIds ?? [])];
    if (ids.length === 0) return false;
    for (const id of ids) {
      const v = await client.policyVersion.findUnique({
        where: { id },
        select: { contentHash: true, policy: { select: { name: true } } },
      });
      if (
        v?.policy.name !== START_MODE_POLICY_NAME ||
        modeForContentHash(v.contentHash) !== 'ask'
      )
        return false;
    }
    return true;
  }

  /** A person already approved a fetch to this origin on this device. */
  private async siteSeen(
    client: TenantPrismaClient,
    hostId: string,
    scope: string,
  ): Promise<boolean> {
    const origin = scope.slice(0, -1); // `https://host/`
    const seen = await client.hostApproval.findFirst({
      where: {
        hostId,
        actionId: 'webfetch',
        status: 'APPROVED',
        decidedBy: { not: null },
        resource: { startsWith: origin },
      },
      select: { id: true },
    });
    return seen !== null;
  }

  /** Per device: is it learning, and until when (for the device list and the enforcement label). */
  async windows(
    tenantId: string,
    hosts: Array<{
      id: string;
      firstApprovedAt: Date | null;
      learningStartedAt: Date | null;
      learningOff: boolean;
    }>,
    now: Date = new Date(),
  ): Promise<Map<string, { active: boolean; endsAt: Date | null }>> {
    const cfg = await this.config(tenantId);
    return new Map(
      hosts.map((h) => [
        h.id,
        cfg.enabled
          ? learningWindow(h, cfg.days, now)
          : { active: false, endsAt: null },
      ]),
    );
  }

  /** "Here is what Manar saw this week". */
  async summary(
    client: TenantPrismaClient,
    tenantId: string,
    now: Date = new Date(),
  ) {
    const cfg = await this.config(tenantId);
    const since = new Date(now.getTime() - 14 * DAY);
    const [hosts, rows] = await Promise.all([
      client.host.findMany({
        where: { status: 'APPROVED', removedAt: null },
        select: {
          id: true,
          hostname: true,
          firstApprovedAt: true,
          learningStartedAt: true,
          learningOff: true,
        },
        orderBy: { createdAt: 'desc' },
        take: 200,
      }),
      client.learningObservation.findMany({
        where: { lastSeenAt: { gte: since } },
        orderBy: [{ count: 'desc' }, { lastSeenAt: 'desc' }],
        take: 500,
      }),
    ]);
    const win = await this.windows(tenantId, hosts, now);
    const name = new Map(hosts.map((h) => [h.id, h.hostname]));
    const per = new Map<string, number>();
    for (const r of rows) per.set(r.hostId, (per.get(r.hostId) ?? 0) + r.count);
    return {
      learning: cfg,
      totalWouldHaveAsked: rows.reduce((a, r) => a + r.count, 0),
      devices: hosts
        .map((h) => ({
          hostId: h.id,
          hostname: h.hostname,
          learning: {
            active: win.get(h.id)?.active ?? false,
            endsAt: win.get(h.id)?.endsAt ?? null,
            off: h.learningOff,
          },
          wouldHaveAsked: per.get(h.id) ?? 0,
        }))
        .filter((d) => d.learning.active || d.wouldHaveAsked > 0),
      suggestions: rows
        .filter(
          (r) =>
            r.state === 'NEW' &&
            r.scope !== UNSCOPED &&
            r.count >= SUGGEST_AFTER,
        )
        .map((r) => ({
          id: r.id,
          hostId: r.hostId,
          hostname: name.get(r.hostId) ?? null,
          toolId: r.toolId,
          actionId: r.actionId,
          scope: r.scope,
          count: r.count,
          lastSeenAt: r.lastSeenAt,
          lastsDays: Math.round(ALWAYS_GRANT_TTL_MS / 86_400_000),
        })),
    };
  }

  /** One tap: a one-year, device-scoped, withdrawable "always allow" of exactly what was seen. */
  async accept(
    client: TenantPrismaClient,
    tenantId: string,
    id: string,
    actor: Actor,
  ) {
    const o = await client.learningObservation.findUnique({ where: { id } });
    if (!o) throw new NotFoundException('That suggestion was not found.');
    if (o.state !== 'NEW' || o.scope === UNSCOPED || !o.askKey)
      throw new ConflictException('That suggestion was already answered.');
    const host = await client.host.findUnique({
      where: { id: o.hostId },
      select: { status: true, removedAt: true },
    });
    if (!host || host.status !== 'APPROVED' || host.removedAt)
      throw new ConflictException(
        'That device is no longer in this workspace.',
      );
    // The stored scope must still be one the matcher accepts: probe it with a path inside it.
    const probe = o.scope.endsWith('*') ? `${o.scope.slice(0, -1)}x` : o.scope;
    if (!scopeMatches(o.scope, o.toolId, o.actionId, probe))
      throw new BadRequestException(
        'That suggestion cannot be turned into a rule.',
      );
    const now = new Date();
    const grant = await client.$transaction(async (tx) => {
      const won = await tx.learningObservation.updateMany({
        where: { id, state: 'NEW' },
        data: { state: 'ACCEPTED', decidedAt: now },
      });
      if (won.count === 0)
        throw new ConflictException('That suggestion was already answered.');
      return createAllowGrant(tx, {
        scope: { hostId: o.hostId },
        target: { toolId: o.toolId, actionId: o.actionId, resource: probe },
        createdBy: actor.id,
        sourceId: o.id,
        now,
        always: { origin: 'learning', pattern: o.scope, askKey: o.askKey },
      });
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_CREATED,
      actor: { type: 'human', id: actor.id },
      data: {
        grantId: grant.id,
        hostId: o.hostId,
        toolId: o.toolId,
        actionId: o.actionId,
        origin: 'learning',
        scope: o.scope,
      },
    });
    await this.decided(client, tenantId, actor, o, 'accepted');
    return {
      id: o.id,
      grantId: grant.id,
      expiresAt: new Date(now.getTime() + ALWAYS_GRANT_TTL_MS),
    };
  }

  async dismiss(
    client: TenantPrismaClient,
    tenantId: string,
    id: string,
    actor: Actor,
  ) {
    const o = await client.learningObservation.findUnique({ where: { id } });
    if (!o) throw new NotFoundException('That suggestion was not found.');
    const won = await client.learningObservation.updateMany({
      where: { id, state: 'NEW' },
      data: { state: 'DISMISSED', decidedAt: new Date() },
    });
    if (won.count === 0)
      throw new ConflictException('That suggestion was already answered.');
    await this.decided(client, tenantId, actor, o, 'dismissed');
    return { id };
  }

  private decided(
    client: TenantPrismaClient,
    tenantId: string,
    actor: Actor,
    o: {
      id: string;
      hostId: string;
      toolId: string;
      actionId: string;
      scope: string;
    },
    outcome: 'accepted' | 'dismissed',
  ) {
    return this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.LEARNING_SUGGESTION_DECIDED,
      actor: { type: 'human', id: actor.id },
      data: {
        suggestionId: o.id,
        hostId: o.hostId,
        toolId: o.toolId,
        actionId: o.actionId,
        scope: o.scope,
        outcome,
      },
    });
  }

  /** Admin: turn learning off for one device, switch it on again, or restart its 7 days. */
  async setDevice(
    client: TenantPrismaClient,
    tenantId: string,
    hostId: string,
    action: 'off' | 'on' | 'restart',
    actor: Actor,
  ) {
    const data =
      action === 'off'
        ? { learningOff: true }
        : action === 'on'
          ? { learningOff: false }
          : { learningOff: false, learningStartedAt: new Date() };
    const won = await client.host.updateMany({
      where: { id: hostId, removedAt: null },
      data,
    });
    if (won.count === 0) throw new NotFoundException('Device not found.');
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.LEARNING_CHANGED,
      actor: { type: 'human', id: actor.id },
      data: { scope: 'device', hostId, value: action },
    });
    return { hostId, action };
  }
}
