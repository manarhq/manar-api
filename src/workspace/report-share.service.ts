import { randomBytes } from 'node:crypto';
import { Injectable, NotFoundException } from '@nestjs/common';
import type { Prisma } from '../generated/control-client/client';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { ReportCardTotals } from './report-card.service';

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

  async publicView(shareId: string): Promise<ReportCardTotals> {
    if (!SHARE_ID.test(shareId)) throw new NotFoundException();
    const row = await this.control.reportShare.findUnique({
      where: { id: shareId },
    });
    if (!row || row.revokedAt) throw new NotFoundException();
    return publicTotals(row.totals as unknown as ReportCardTotals);
  }
}
