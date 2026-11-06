import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import {
  decisionRights,
  refusalMessage,
  STEP_UP_MAX_AGE_SECONDS,
  type Choice,
  type DecisionRights,
} from '../approvals/decision-rights';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditActor } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  cursorWhereClause,
  toCursorPage,
  type CursorPage,
  type DecodedCursor,
} from '../common/pagination/cursor-pagination';
import type {
  PrismaClient as TenantPrismaClient,
  SecretEvent,
} from '../generated/tenant-client/client';
import { SecretAlertBus } from './secret-alert-bus';
import { TAMPER_EVENT_TYPES } from '../hosts/tamper';
import {
  blockFeatures,
  DEFAULT_BLOCK_MODE,
  maskHome,
  SERVICE_EVENT_TYPES,
  type BlockMode,
  type HostEvent,
} from './secrets.validation';

export class SecretsNotFoundError extends Error {}

export type VaultDecision = 'ALLOW_ONCE' | 'ALLOW_8H' | 'ALLOW_ALWAYS' | 'DENY';

/** Who answers a vault request in the console. */
export interface VaultDecider {
  /** Keycloak subject, compared with the device's owner. */
  subject: string;
  /** Holds an approver role. */
  admin: boolean;
  company: boolean;
  /** Signed in within STEP_UP_MAX_AGE_SECONDS (the step-up until passkeys, Phase A). */
  freshSignIn: boolean;
}

const CHOICE: Record<VaultDecision, Choice> = {
  ALLOW_ONCE: 'approve_once',
  ALLOW_8H: 'approve_8h',
  ALLOW_ALWAYS: 'approve_always',
  DENY: 'deny',
};
const EIGHT_HOURS_MS = 8 * 3_600_000;
const STANDING = ['ALLOW_8H', 'ALLOW_ALWAYS'];

/**
 * What a person may answer to "may this program have this secret": the approval rights of a
 * secret handover (decision-rights.ts). In a company an approver never releases a secret to their
 * own device; another approver must. A personal owner allows once or 8 hours after a fresh
 * sign-in, never always. "Always" is a company approver's answer for someone else's device.
 */
export function vaultRights(
  who: VaultDecider,
  ownerSubject: string | null,
): DecisionRights & { decisions: VaultDecision[] } {
  const rights = decisionRights({
    admin: who.admin,
    owner: !!ownerSubject && ownerSubject === who.subject,
    adminsOnly: false,
    company: who.company,
    sensitive: 'handover',
    actionId: 'secret.use',
  });
  const choices: Choice[] =
    who.company && who.admin && rights.choices.includes('approve_8h')
      ? [
          ...rights.choices.filter((c) => c !== 'deny'),
          'approve_always',
          'deny',
        ]
      : rights.choices;
  const decisions = (Object.keys(CHOICE) as VaultDecision[]).filter((d) =>
    choices.includes(CHOICE[d]),
  );
  return { ...rights, choices, decisions };
}
export class SecretsConflictError extends Error {}

const WATCH_TYPES = ['secret.watch.available', 'secret.watch.unavailable'];
/** Not secrets: shown on the device (tampered), not in the secrets timeline. */
const NOT_IN_TIMELINE = [
  ...WATCH_TYPES,
  ...SERVICE_EVENT_TYPES,
  ...TAMPER_EVENT_TYPES,
];
const FUTURE_SLACK_MS = 5 * 60_000;
const ACCESS_TTL_MS = 10 * 60_000;
const MAX_PENDING_ACCESS_PER_HOST = 50;
const EVENTS_PER_MINUTE = 600;
const hostActor = (hostId: string): AuditActor => ({
  type: 'system',
  id: `host:${hostId}`,
});

export interface TimelineQuery {
  hostId?: string;
  toolId?: string;
  type?: string;
  from?: Date;
  to?: Date;
  limit: number;
  cursor?: DecodedCursor;
}

/** Watcher events, the vault and its access requests. Every query is on the caller's tenant client. */
@Injectable()
export class SecretsService {
  /** Events accepted per device in the current minute. In memory per pod: a ceiling, not an exact count. */
  private readonly windows = new Map<
    string,
    { start: number; count: number }
  >();

  constructor(
    private readonly audit: AuditService,
    private readonly bus: SecretAlertBus,
  ) {}

  private throttle(hostId: string, n: number): void {
    const now = Date.now();
    if (this.windows.size > 10_000) this.windows.clear();
    let w = this.windows.get(hostId);
    if (!w || now - w.start >= 60_000) {
      w = { start: now, count: 0 };
      this.windows.set(hostId, w);
    }
    if (w.count + n > EVENTS_PER_MINUTE) {
      throw new HttpException(
        'Too many events from this device',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    w.count += n;
  }

  /** `POST /host/v1/events`: stores a validated batch, audits secret.* and protect.tamper.*, raises alerts. */
  async ingest(
    client: TenantPrismaClient,
    tenantId: string,
    hostId: string,
    events: HostEvent[],
  ): Promise<{ accepted: number }> {
    this.throttle(hostId, events.length);
    const now = Date.now();
    const rows = events.map((e) => ({
      hostId,
      type: e.type,
      toolId: e.toolId ?? null,
      process: e.process ?? null,
      pathClass: e.pathClass ?? null,
      maskedPath: e.maskedPath ? maskHome(e.maskedPath) : null,
      blocked: e.blocked ?? false,
      at: new Date(Math.min(e.at.getTime(), now + FUTURE_SLACK_MS)),
    }));
    await client.secretEvent.createMany({ data: rows });
    for (const [i, r] of rows.entries()) {
      const downtimeSeconds = events[i]!.downtimeSeconds;
      if (WATCH_TYPES.includes(r.type)) continue;
      await this.audit.recordSafely(client, tenantId, {
        eventType:
          r.type as (typeof AUDIT_EVENT_TYPES)[keyof typeof AUDIT_EVENT_TYPES],
        actor: hostActor(hostId),
        data: {
          hostId,
          toolId: r.toolId,
          process: r.process,
          pathClass: r.pathClass,
          maskedPath: r.maskedPath,
          blocked: r.blocked,
          at: r.at.toISOString(),
          ...(downtimeSeconds !== undefined ? { downtimeSeconds } : {}),
        },
      });
      if (r.type === 'secret.touched' && r.toolId) {
        this.bus.emit({
          tenantId,
          hostId,
          toolId: r.toolId,
          process: r.process ?? '',
          pathClass: r.pathClass ?? '',
          maskedPath: r.maskedPath ?? '',
          blocked: r.blocked,
          at: r.at,
        });
      }
    }
    return { accepted: rows.length };
  }

  async timeline(
    client: TenantPrismaClient,
    q: TimelineQuery,
  ): Promise<CursorPage<SecretEvent & { hostname: string | null }>> {
    const rows = await client.secretEvent.findMany({
      where: {
        ...(q.hostId ? { hostId: q.hostId } : {}),
        ...(q.toolId ? { toolId: q.toolId } : {}),
        type: q.type ? q.type : { notIn: NOT_IN_TIMELINE },
        ...(q.from || q.to
          ? {
              at: {
                ...(q.from ? { gte: q.from } : {}),
                ...(q.to ? { lte: q.to } : {}),
              },
            }
          : {}),
        ...cursorWhereClause('at', q.cursor),
      },
      orderBy: [{ at: 'desc' }, { id: 'desc' }],
      take: q.limit + 1,
    });
    const page = toCursorPage(rows, q.limit, (r) => r.at);
    const hosts = await client.host.findMany({
      where: { id: { in: [...new Set(page.items.map((r) => r.hostId))] } },
      select: { id: true, hostname: true },
    });
    const names = new Map(hosts.map((h) => [h.id, h.hostname]));
    return {
      nextCursor: page.nextCursor,
      items: page.items.map((r) => ({
        ...r,
        hostname: names.get(r.hostId) ?? null,
      })),
    };
  }

  /** What each tool touched in the last `days` days, per path class; plus watcher status and vault per device. */
  async overview(client: TenantPrismaClient, days: number) {
    const since = new Date(Date.now() - days * 86_400_000);
    const [groups, hosts, vault, pending] = await Promise.all([
      client.secretEvent.groupBy({
        by: ['toolId', 'pathClass', 'blocked'],
        where: {
          type: 'secret.touched',
          at: { gte: since },
          toolId: { not: null },
        },
        _count: { _all: true },
        _max: { at: true },
      }),
      client.host.findMany({
        where: { status: 'APPROVED' },
        select: { id: true, hostname: true, os: true },
        orderBy: { hostname: 'asc' },
        take: 200,
      }),
      client.secretVault.findMany({
        orderBy: { createdAt: 'desc' },
        take: 500,
      }),
      client.secretVaultAccess.count({
        where: {
          status: 'PENDING',
          createdAt: { gte: new Date(Date.now() - ACCESS_TTL_MS) },
        },
      }),
    ]);
    const tools = new Map<
      string,
      {
        toolId: string;
        touched: number;
        blocked: number;
        classes: Record<string, number>;
        lastAt: Date | null;
      }
    >();
    for (const g of groups) {
      const id = g.toolId as string;
      const t = tools.get(id) ?? {
        toolId: id,
        touched: 0,
        blocked: 0,
        classes: {},
        lastAt: null,
      };
      t.touched += g._count._all;
      if (g.blocked) t.blocked += g._count._all;
      if (g.pathClass)
        t.classes[g.pathClass] = (t.classes[g.pathClass] ?? 0) + g._count._all;
      if (g._max.at && (!t.lastAt || g._max.at > t.lastAt))
        t.lastAt = g._max.at;
      tools.set(id, t);
    }
    const devices = await Promise.all(
      hosts.map(async (h) => {
        const last = await client.secretEvent.findFirst({
          where: { hostId: h.id, type: { in: WATCH_TYPES } },
          orderBy: [{ at: 'desc' }, { id: 'desc' }],
          select: { type: true, at: true },
        });
        return {
          hostId: h.id,
          hostname: h.hostname,
          os: h.os,
          // Honest label: no report at all is "unknown", never a green tick.
          watcher: !last
            ? 'unknown'
            : last.type === 'secret.watch.available'
              ? 'ok'
              : 'monitoring unavailable',
          vault: vault.filter((v) => v.hostId === h.id),
        };
      }),
    );
    return {
      days,
      tools: [...tools.values()].sort((a, b) => b.touched - a.touched),
      devices,
      pendingAccess: pending,
    };
  }

  private async approvedHost(client: TenantPrismaClient, hostId: string) {
    const host = await client.host.findUnique({ where: { id: hostId } });
    if (!host || host.status !== 'APPROVED') {
      throw new SecretsNotFoundError('No approved device with that id');
    }
    return host;
  }

  /** Console: ask a device to move one secret into its vault. */
  async requestVault(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    hostId: string,
    kind: string,
    ref: string,
  ) {
    await this.approvedHost(client, hostId);
    const existing = await client.secretVault.findUnique({
      where: { hostId_kind_ref: { hostId, kind, ref } },
    });
    if (
      existing &&
      (existing.state === 'STORED' || existing.state === 'RESTORE_REQUESTED')
    ) {
      throw new SecretsConflictError('This secret is already in the vault');
    }
    const row = await client.secretVault.upsert({
      where: { hostId_kind_ref: { hostId, kind, ref } },
      create: { hostId, kind, ref, requestedBy: actor.id },
      update: { state: 'REQUESTED', requestedBy: actor.id, detail: null },
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.SECRET_VAULT_REQUESTED,
      actor,
      data: { hostId, kind, ref },
    });
    return row;
  }

  /** Console: "Restore to file". */
  async requestRestore(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    hostId: string,
    kind: string,
    ref: string,
  ) {
    await this.approvedHost(client, hostId);
    const row = await client.secretVault.findUnique({
      where: { hostId_kind_ref: { hostId, kind, ref } },
    });
    if (!row || row.state !== 'STORED') {
      throw new SecretsConflictError('This secret is not in the vault');
    }
    const updated = await client.secretVault.update({
      where: { id: row.id },
      data: { state: 'RESTORE_REQUESTED' },
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.SECRET_VAULT_RESTORE_REQUESTED,
      actor,
      data: { hostId, kind, ref },
    });
    return updated;
  }

  /** Device: what to do now. */
  async instructions(client: TenantPrismaClient, hostId: string) {
    const rows = await client.secretVault.findMany({
      where: { hostId, state: { in: ['REQUESTED', 'RESTORE_REQUESTED'] } },
      orderBy: { createdAt: 'asc' },
      take: 50,
    });
    return {
      vault: rows.map((r) => ({
        kind: r.kind,
        ref: r.ref,
        action: r.state === 'REQUESTED' ? 'store' : 'restore',
      })),
    };
  }

  /** Device: the result of an instruction (after it verified the read-back, for STORED). */
  async report(
    client: TenantPrismaClient,
    tenantId: string,
    hostId: string,
    kind: string,
    ref: string,
    state: 'STORED' | 'RESTORED' | 'FAILED' | 'AVAILABLE',
    detail?: string,
  ) {
    const row = await client.secretVault.findUnique({
      where: { hostId_kind_ref: { hostId, kind, ref } },
    });
    if (state === 'AVAILABLE') {
      // The device found a key it could move. It only offers; nothing moves until a person asks.
      if (!row) {
        await client.secretVault.create({
          data: {
            hostId,
            kind,
            ref,
            state: 'AVAILABLE',
            requestedBy: 'device',
          },
        });
      } else if (['RESTORED', 'FAILED'].includes(row.state)) {
        await client.secretVault.update({
          where: { id: row.id },
          data: { state: 'AVAILABLE', detail: null },
        });
      }
      return { state: 'AVAILABLE' };
    }
    // `manar-edge vault add` / `vault restore` on the device are not console requests: they may
    // report a move or a restore nobody asked for here.
    if (state === 'STORED' && !row) {
      await client.secretVault.create({
        data: { hostId, kind, ref, state: 'STORED', requestedBy: 'device' },
      });
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.SECRET_VAULT_STORED,
        actor: hostActor(hostId),
        data: { hostId, kind, ref },
      });
      return { state: 'STORED' };
    }
    if (!row) throw new SecretsNotFoundError('No such vault entry');
    let next: string;
    if (
      state === 'STORED' &&
      ['REQUESTED', 'AVAILABLE', 'RESTORED', 'FAILED'].includes(row.state)
    )
      next = 'STORED';
    else if (
      state === 'RESTORED' &&
      ['RESTORE_REQUESTED', 'STORED'].includes(row.state)
    )
      next = 'RESTORED';
    else if (state === 'FAILED')
      next = row.state === 'RESTORE_REQUESTED' ? 'STORED' : 'FAILED';
    else
      throw new SecretsConflictError(
        'That report does not fit the entry state',
      );
    await client.secretVault.update({
      where: { id: row.id },
      data: { state: next, detail: detail ?? null },
    });
    if (state !== 'FAILED') {
      await this.audit.recordSafely(client, tenantId, {
        eventType:
          state === 'STORED'
            ? AUDIT_EVENT_TYPES.SECRET_VAULT_STORED
            : AUDIT_EVENT_TYPES.SECRET_VAULT_RESTORED,
        actor: hostActor(hostId),
        data: { hostId, kind, ref },
      });
    }
    return { state: next };
  }

  /** Device: a program wants a vaulted secret. One open request per (device, secret, program). */
  async createAccess(
    client: TenantPrismaClient,
    hostId: string,
    kind: string,
    ref: string,
    program: { name: string; path: string; sha: string },
  ) {
    if (kind !== 'file' && kind !== 'ssh-restore') {
      const vault = await client.secretVault.findUnique({
        where: { hostId_kind_ref: { hostId, kind, ref } },
      });
      if (!vault || vault.state !== 'STORED') {
        throw new SecretsNotFoundError('That secret is not in the vault');
      }
    }
    const fresh = new Date(Date.now() - ACCESS_TTL_MS);
    const open = await client.secretVaultAccess.findFirst({
      where: {
        hostId,
        kind,
        ref,
        programSha: program.sha,
        programPath: program.path,
        status: 'PENDING',
        createdAt: { gte: fresh },
      },
    });
    if (open) return { id: open.id, status: open.status };
    const count = await client.secretVaultAccess.count({
      where: { hostId, status: 'PENDING', createdAt: { gte: fresh } },
    });
    if (count >= MAX_PENDING_ACCESS_PER_HOST) {
      throw new SecretsConflictError('Too many open requests for this device');
    }
    const row = await client.secretVaultAccess.create({
      data: {
        hostId,
        kind,
        ref,
        program: program.name,
        programPath: program.path,
        programSha: program.sha,
      },
    });
    return { id: row.id, status: row.status };
  }

  /** Device: poll one request (only its own). An old PENDING reads as DENY. */
  async getAccess(client: TenantPrismaClient, hostId: string, id: string) {
    const row = await client.secretVaultAccess.findFirst({
      where: { id, hostId },
    });
    if (!row) throw new SecretsNotFoundError('No such request');
    const expired =
      row.status === 'PENDING' &&
      row.createdAt.getTime() < Date.now() - ACCESS_TTL_MS;
    return { id: row.id, status: expired ? 'DENY' : row.status };
  }

  /** The workspace's blocking mode (`keys` until the owner picks another). */
  async blockMode(client: TenantPrismaClient): Promise<BlockMode> {
    const row = await client.secretSettings.findUnique({
      where: { id: 'default' },
    });
    return (row?.blockMode as BlockMode | undefined) ?? DEFAULT_BLOCK_MODE;
  }

  /**
   * Device feature flags for the workspace's mode. `secrets.vault.ssh` means the option to move an
   * ssh key into the vault is offered; the person still clicks per key.
   */
  async features(client: TenantPrismaClient): Promise<string[]> {
    return [
      ...blockFeatures(await this.blockMode(client)),
      'secrets.vault.ssh',
    ];
  }

  async setBlockMode(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    blockMode: BlockMode,
  ) {
    const before = await this.blockMode(client);
    await client.secretSettings.upsert({
      where: { id: 'default' },
      create: { id: 'default', blockMode, updatedBy: actor.id },
      update: { blockMode, updatedBy: actor.id },
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.SECRET_SETTINGS_CHANGED,
      actor,
      data: { from: before, to: blockMode },
    });
    return { blockMode };
  }

  /** Console: open requests (newest first), each with what this person may answer. */
  async listAccess(client: TenantPrismaClient, who: VaultDecider) {
    const rows = await client.secretVaultAccess.findMany({
      where: {
        status: 'PENDING',
        createdAt: { gte: new Date(Date.now() - ACCESS_TTL_MS) },
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
    const hosts = rows.length
      ? await client.host.findMany({
          where: { id: { in: [...new Set(rows.map((r) => r.hostId))] } },
          select: { id: true, ownerSubject: true },
        })
      : [];
    const owner = new Map(hosts.map((h) => [h.id, h.ownerSubject]));
    return rows.map((r) => {
      const rights = vaultRights(who, owner.get(r.hostId) ?? null);
      return {
        ...r,
        allowedDecisions: rights.decisions,
        needs: rights.needs,
        stepUpNeeded: rights.stepUp && !who.freshSignIn,
      };
    });
  }

  /** "8 hours" and "Always" answers still in force (not withdrawn, not ended). */
  private standingWhere(now: Date) {
    return {
      status: { in: STANDING },
      withdrawnAt: null,
      OR: [
        { status: 'ALLOW_ALWAYS', expiresAt: null },
        { expiresAt: { gt: now } },
      ],
    };
  }

  /**
   * Device config (`vaultGrants`): the standing grants the device may keep. The device drops any
   * local grant not in this list, so a withdrawal takes effect at its next config read.
   */
  async vaultGrants(client: TenantPrismaClient, hostId: string) {
    const rows = await client.secretVaultAccess.findMany({
      where: { hostId, ...this.standingWhere(new Date()) },
      select: { id: true, status: true, expiresAt: true },
      orderBy: { createdAt: 'asc' },
      take: 500,
    });
    return rows.map((r) => ({
      id: r.id,
      until: r.expiresAt?.toISOString() ?? null,
    }));
  }

  /** Console: standing grants per device, to withdraw. */
  async listGrants(client: TenantPrismaClient) {
    const rows = await client.secretVaultAccess.findMany({
      where: this.standingWhere(new Date()),
      orderBy: { decidedAt: 'desc' },
      take: 500,
    });
    return rows.map((r) => ({
      id: r.id,
      hostId: r.hostId,
      kind: r.kind,
      ref: r.ref,
      program: r.program,
      programPath: r.programPath,
      decision: r.status as 'ALLOW_8H' | 'ALLOW_ALWAYS',
      decidedAt: r.decidedAt,
      until: r.expiresAt,
    }));
  }

  /** Console: withdraw a standing grant. Audited once; withdrawing again changes nothing. */
  async withdrawGrant(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
  ) {
    const now = new Date();
    const done = await client.secretVaultAccess.updateMany({
      where: { id, status: { in: STANDING }, withdrawnAt: null },
      data: { withdrawnAt: now, withdrawnBy: actor.id },
    });
    const row = await client.secretVaultAccess.findUnique({ where: { id } });
    if (!row || !STANDING.includes(row.status))
      throw new SecretsNotFoundError('No such permission');
    if (done.count === 1)
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.SECRET_VAULT_GRANT_WITHDRAWN,
        actor,
        data: {
          grantId: id,
          hostId: row.hostId,
          kind: row.kind,
          ref: row.ref,
          program: row.program,
          decision: row.status,
        },
      });
    return { id, withdrawn: true as const };
  }

  /** Console: the person's decision. Audited as released or denied. */
  async decideAccess(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
    decision: VaultDecision,
    who: VaultDecider,
  ) {
    const row = await client.secretVaultAccess.findUnique({ where: { id } });
    if (!row) throw new SecretsNotFoundError('No such request');
    // The approval rights apply here, where every console decision arrives (fail closed: an
    // unknown owner is nobody's own device in a company, and the owner's in a personal workspace).
    const host = await client.host.findUnique({
      where: { id: row.hostId },
      select: { ownerSubject: true },
    });
    const rights = vaultRights(who, host?.ownerSubject ?? null);
    if (!rights.decisions.includes(decision))
      throw new ForbiddenException(
        decision === 'ALLOW_ALWAYS' && rights.decisions.includes('ALLOW_8H')
          ? 'Always is not offered here: allow once or for 8 hours, or make a rule. Nothing was changed.'
          : refusalMessage(rights),
      );
    if (rights.stepUp && decision !== 'DENY' && !who.freshSignIn)
      throw new UnauthorizedException({
        statusCode: 401,
        code: 'reauth_required',
        maxAge: STEP_UP_MAX_AGE_SECONDS,
        message:
          'Confirm it is you (sign in again) to release a secret to your own device. Nothing was changed.',
      });
    const now = new Date();
    const done = await client.secretVaultAccess.updateMany({
      where: {
        id,
        status: 'PENDING',
        createdAt: { gte: new Date(Date.now() - ACCESS_TTL_MS) },
      },
      data: {
        status: decision,
        decidedBy: actor.id,
        decidedAt: now,
        expiresAt:
          decision === 'ALLOW_8H'
            ? new Date(now.getTime() + EIGHT_HOURS_MS)
            : null,
      },
    });
    if (done.count !== 1)
      throw new SecretsConflictError(
        'This request was already decided or has expired',
      );
    await this.audit.recordSafely(client, tenantId, {
      eventType:
        decision === 'DENY'
          ? AUDIT_EVENT_TYPES.SECRET_VAULT_DENIED
          : AUDIT_EVENT_TYPES.SECRET_VAULT_RELEASED,
      actor,
      data: {
        hostId: row.hostId,
        kind: row.kind,
        ref: row.ref,
        program: row.program,
        programPath: row.programPath,
        programSha: row.programSha,
        decision,
      },
    });
    await client.secretEvent.create({
      data: {
        hostId: row.hostId,
        type:
          decision === 'DENY' ? 'secret.vault.denied' : 'secret.vault.released',
        process: row.program,
        pathClass: row.kind,
        maskedPath: row.ref,
        blocked: decision === 'DENY',
        at: new Date(),
      },
    });
    return { id, status: decision };
  }
}
