import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { ControlPrismaService } from '../database/control-prisma.service';
import { GrowthAuditService } from '../growth/growth-audit.service';
import { PostHogClient, type PostHogEvent } from './posthog.client';
import { isSecretKey, REDACTED, redactText } from './redact';

export const SAMPLE_RETENTION_DAYS = 365;

export interface Flags {
  improveManar: boolean;
  aiTraining: boolean;
}
type Prop = string | number | boolean;
type Props = Record<string, Prop>;
interface OrgRow {
  kind: string;
  dataImproveManar: boolean;
  dataAiTraining: boolean;
}

/** The org flags count only for company workspaces; personal (and sample) workspaces have none. */
export const orgFlags = (t: OrgRow): Flags | null =>
  t.kind === 'COMPANY'
    ? { improveManar: t.dataImproveManar, aiTraining: t.dataAiTraining }
    : null;

/** Effective = user AND org (org on when there is none). `aiTraining` means nothing while `improveManar` is off. */
export function effectiveFlags(user: Flags, org: Flags | null): Flags {
  const improveManar = user.improveManar && (org?.improveManar ?? true);
  return {
    improveManar,
    aiTraining: improveManar && user.aiTraining && (org?.aiTraining ?? true),
  };
}

export interface DeviceTelemetry {
  version: string;
  os: string;
  arch: string;
  events: { type: string; at: string; data?: Props }[];
  samples: {
    kind: string;
    tool: string;
    decision: string;
    text: string;
    at: string;
  }[];
}

const toDate = (s: string) => {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? new Date() : d;
};

@Injectable()
export class DataCollectionService {
  private readonly logger = new Logger(DataCollectionService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly posthog: PostHogClient,
    private readonly audit: GrowthAuditService,
  ) {}

  // ---- preferences ----

  private async userFlags(issuer: string, subject: string) {
    const row = await this.control.userDataPreference.findUnique({
      where: { issuer_subject: { issuer, subject } },
    });
    return {
      improveManar: row?.improveManar ?? true,
      aiTraining: row?.aiTraining ?? true,
      noticeDismissed: row?.noticeDismissed ?? false,
    };
  }

  private tenantRow(tenantId: string) {
    return this.control.tenant.findUniqueOrThrow({
      where: { id: tenantId },
      select: { kind: true, dataImproveManar: true, dataAiTraining: true },
    });
  }

  async getMine(issuer: string, subject: string, tenantId: string) {
    const user = await this.userFlags(issuer, subject);
    const org = orgFlags(await this.tenantRow(tenantId));
    return {
      improveManar: user.improveManar,
      aiTraining: user.aiTraining,
      org,
      effective: effectiveFlags(user, org),
      noticeDismissed: user.noticeDismissed,
    };
  }

  async setMine(
    issuer: string,
    subject: string,
    tenantId: string,
    patch: Partial<Flags> & { noticeDismissed?: boolean },
  ) {
    await this.control.userDataPreference.upsert({
      where: { issuer_subject: { issuer, subject } },
      create: { issuer, subject, ...patch },
      update: patch,
    });
    if (patch.improveManar === false)
      await this.deleteUserData(issuer, subject);
    // Revocation: samples already stored stop being usable for training.
    if (patch.aiTraining === false)
      await this.control.productSample.updateMany({
        where: { issuer, subject },
        data: { aiTrainingAllowed: false },
      });
    return this.getMine(issuer, subject, tenantId);
  }

  async getOrg(tenantId: string): Promise<Flags> {
    const t = await this.tenantRow(tenantId);
    return { improveManar: t.dataImproveManar, aiTraining: t.dataAiTraining };
  }

  async setOrg(tenantId: string, userId: string, patch: Partial<Flags>) {
    const before = await this.getOrg(tenantId);
    await this.control.tenant.update({
      where: { id: tenantId },
      data: {
        ...(patch.improveManar !== undefined && {
          dataImproveManar: patch.improveManar,
        }),
        ...(patch.aiTraining !== undefined && {
          dataAiTraining: patch.aiTraining,
        }),
      },
    });
    // The workspace stopped collecting: what its devices already sent is deleted too.
    if (patch.improveManar === false && before.improveManar)
      await this.control.productSample.deleteMany({ where: { tenantId } });
    if (patch.aiTraining === false && before.aiTraining)
      await this.control.productSample.updateMany({
        where: { tenantId },
        data: { aiTrainingAllowed: false },
      });
    const after = await this.getOrg(tenantId);
    await this.audit.record(
      tenantId,
      AUDIT_EVENT_TYPES.WORKSPACE_DATA_PREFERENCES_CHANGED,
      { type: 'human', id: userId },
      { before, after },
    );
    return after;
  }

  // ---- deletion and retention ----

  /** Samples now, and the PostHog person when PostHog is configured. Used on opt-out and account deletion. */
  async deleteUserData(issuer: string, subject: string): Promise<number> {
    const { count } = await this.control.productSample.deleteMany({
      where: { issuer, subject },
    });
    await this.posthog.deletePerson(this.posthog.distinctId(issuer, subject));
    return count;
  }

  async purgeOld(now = new Date()): Promise<{ deleted: number }> {
    const cutoff = new Date(now.getTime() - SAMPLE_RETENTION_DAYS * 86_400_000);
    // The hourly purge can meet a large backlog. The control role's statement_timeout is 30 s
    // (set on the role because the pool goes through PgBouncer), so this one transaction raises
    // it for itself: SET LOCAL lasts to the end of the transaction and is safe in transaction
    // pooling, unlike a session SET.
    const { count } = await this.control.$transaction(
      async (tx) => {
        await tx.$executeRaw`SET LOCAL statement_timeout = '120s'`;
        return tx.productSample.deleteMany({
          where: { createdAt: { lt: cutoff } },
        });
      },
      { timeout: 130_000 },
    );
    return { deleted: count };
  }

  // ---- console events ----

  private async context(tenantId: string) {
    const [ent, t] = await Promise.all([
      this.control.tenantEntitlement.findUnique({ where: { tenantId } }),
      this.tenantRow(tenantId),
    ]);
    return {
      org: orgFlags(t),
      props: {
        plan: ent?.plan ?? 'free',
        workspace_kind: t.kind.toLowerCase(),
      },
    };
  }

  /** Returns how many events were forwarded (0 when dropped). */
  async ingestConsole(
    issuer: string,
    subject: string,
    tenantId: string,
    events: { name: string; at: string; props?: Props }[],
  ): Promise<number> {
    if (!this.posthog.enabled) return 0;
    const user = await this.userFlags(issuer, subject);
    const ctx = await this.context(tenantId);
    if (!effectiveFlags(user, ctx.org).improveManar) return 0;
    const distinctId = this.posthog.distinctId(issuer, subject);
    await this.posthog.capture(
      events.map((e) => ({
        event: e.name,
        distinctId,
        at: toDate(e.at),
        properties: { ...cleanProps(e.props), ...ctx.props, source: 'console' },
      })),
    );
    return events.length;
  }

  // ---- device telemetry ----

  /** The device owner's sign-in issuer, from the workspace or the membership. */
  private async ownerIssuer(tenantId: string, subject: string) {
    const t = await this.control.tenant.findUnique({
      where: { id: tenantId },
      select: { ownerIssuer: true, ownerSubject: true },
    });
    if (t?.ownerSubject === subject && t.ownerIssuer) return t.ownerIssuer;
    const m = await this.control.membership.findFirst({
      where: { tenantId, subject, status: 'ACTIVE' },
      select: { issuer: true },
    });
    return m?.issuer ?? null;
  }

  /**
   * The owner's effective flags for a device. Unknown owner (key-less host, left the workspace)
   * reads as off.
   */
  async forHost(tenantId: string, ownerSubject: string | null) {
    const off = { effective: { improveManar: false, aiTraining: false } };
    if (!ownerSubject) return off;
    const issuer = await this.ownerIssuer(tenantId, ownerSubject);
    if (!issuer) return off;
    const [user, ctx] = await Promise.all([
      this.userFlags(issuer, ownerSubject),
      this.context(tenantId),
    ]);
    return {
      issuer,
      subject: ownerSubject,
      ctx,
      effective: effectiveFlags(user, ctx.org),
    };
  }

  /** Returns false when the batch was ignored because the owner's effective `improveManar` is off. */
  async ingestDevice(
    tenantId: string,
    ownerSubject: string | null,
    body: DeviceTelemetry,
  ): Promise<boolean> {
    const h = await this.forHost(tenantId, ownerSubject);
    if (!h.effective.improveManar || !('issuer' in h) || !h.ctx) return false;
    const small = (v: string) => redactText(v, 64);
    body = {
      ...body,
      version: small(body.version),
      os: small(body.os),
      arch: small(body.arch),
    };
    const rows = body.samples
      .map((s) => ({ ...s, tool: small(s.tool), text: redactText(s.text) }))
      .filter((s) => s.text.trim() !== '')
      .map((s) => ({
        id: randomUUID(),
        issuer: h.issuer,
        subject: h.subject,
        tenantId,
        kind: s.kind,
        tool: s.tool,
        decision: s.decision,
        text: s.text,
        at: toDate(s.at),
        aiTrainingAllowed: h.effective.aiTraining,
      }));
    if (rows.length)
      await this.control.productSample.createMany({ data: rows });
    // The owner may have switched off between the check above and the insert: look again, and
    // undo what was just written (by id) so a flip never leaves data behind.
    const now = (await this.forHost(tenantId, ownerSubject)).effective;
    if (rows.length && !now.improveManar)
      await this.control.productSample.deleteMany({
        where: { id: { in: rows.map((r) => r.id) } },
      });
    else if (rows.length && !now.aiTraining && h.effective.aiTraining)
      await this.control.productSample.updateMany({
        where: { id: { in: rows.map((r) => r.id) } },
        data: { aiTrainingAllowed: false },
      });
    if (!now.improveManar) return false;
    const distinctId = this.posthog.distinctId(h.issuer, h.subject);
    const device = { version: body.version, os: body.os, arch: body.arch };
    const events: PostHogEvent[] = body.events.map((e) => ({
      event: `device_${e.type}`,
      distinctId,
      at: toDate(e.at),
      properties: {
        ...cleanProps(e.data),
        ...device,
        ...h.ctx.props,
        source: 'device',
      },
    }));
    await this.posthog.capture(events);
    return true;
  }
}

/**
 * Primitive props only. A secret-looking key redacts the whole value; any other string is redacted
 * as `key=value`, so the assignment rules see the key too, and the prefix is stripped again.
 */
function cleanProps(p: Props | undefined): Props {
  const out: Props = {};
  for (const [k, v] of Object.entries(p ?? {})) {
    if (isSecretKey(k)) out[k] = REDACTED;
    else if (typeof v === 'string') {
      const r = redactText(`${k}=${v}`, 4000 + k.length + 1);
      out[k] = r.startsWith(`${k}=`)
        ? r.slice(k.length + 1)
        : redactText(v, 4000);
    } else out[k] = v;
  }
  return out;
}
