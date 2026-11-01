import { randomBytes } from 'node:crypto';
import { Injectable, NotFoundException } from '@nestjs/common';
import type { Prisma } from '../generated/control-client/client';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { ReportCardTotals } from './report-card.service';
import type { SharedSession } from '../sessions/sessions';

const SHARE_ID = /^[A-Za-z0-9_-]{32}$/;

/** The only fields a public viewer ever gets. */
export function publicTotals(t: ReportCardTotals): ReportCardTotals {
  return {
    from: t.from,
    to: t.to,
    actions: t.actions,
    askedYou: t.askedYou,
    blocked: t.blocked,
    secretsKeptSafe: t.secretsKeptSafe,
    series: [...t.series],
  };
}

@Injectable()
export class ReportShareService {
  constructor(private readonly control: ControlPrismaService) {}

  /** A link to one redacted agent session. The totals are its own counts, so the card renders. */
  async createSession(tenantId: string, userId: string, s: SharedSession) {
    const id = randomBytes(24).toString('base64url');
    const buckets = [0, 0, 0, 0, 0, 0, 0];
    const span = Math.max(1, s.durationSeconds);
    for (const st of s.steps)
      buckets[Math.min(6, Math.floor((st.t / span) * 7))]! += 1;
    const end = new Date(Date.parse(s.startedAt) + s.durationSeconds * 1000);
    const totals: ReportCardTotals = {
      from: s.startedAt,
      to: end.toISOString(),
      actions: s.steps.filter(
        (x) => x.kind !== 'approval' && x.kind !== 'secret',
      ).length,
      askedYou: s.counts.approvals,
      blocked: s.counts.blocked,
      secretsKeptSafe: s.counts.secrets,
      series: buckets,
    };
    const row = await this.control.reportShare.create({
      data: {
        id,
        tenantId,
        createdBy: userId,
        totals: totals as unknown as Prisma.InputJsonValue,
        session: s as unknown as Prisma.InputJsonValue,
      },
    });
    return { shareId: row.id, createdAt: row.createdAt };
  }

  async create(tenantId: string, userId: string, totals: ReportCardTotals) {
    const id = randomBytes(24).toString('base64url'); // 192 bits
    const row = await this.control.reportShare.create({
      data: {
        id,
        tenantId,
        createdBy: userId,
        totals: publicTotals(totals) as unknown as Prisma.InputJsonValue,
      },
    });
    return { shareId: row.id, createdAt: row.createdAt };
  }

  /** Only this tenant's shares. */
  list(tenantId: string) {
    return this.control.reportShare.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
      select: { id: true, createdAt: true, revokedAt: true },
    });
  }

  async revoke(tenantId: string, shareId: string): Promise<void> {
    const r = await this.control.reportShare.updateMany({
      where: { id: shareId, tenantId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (r.count === 0) throw new NotFoundException('Share not found');
  }

  async publicView(
    shareId: string,
  ): Promise<ReportCardTotals & { session?: SharedSession }> {
    if (!SHARE_ID.test(shareId)) throw new NotFoundException();
    const row = await this.control.reportShare.findUnique({
      where: { id: shareId },
    });
    if (!row || row.revokedAt) throw new NotFoundException();
    const totals = publicTotals(row.totals as unknown as ReportCardTotals);
    // Stored already redacted; only the known fields go out.
    return row.session
      ? { ...totals, session: row.session as unknown as SharedSession }
      : totals;
  }
}
