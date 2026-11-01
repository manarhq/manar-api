/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/require-await -- fakes */
import { describe, expect, it } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { nextSundayNight } from './weekly-report.job';
import {
  ReportCardService,
  type ReportCardTotals,
} from './report-card.service';
import { ReportShareService } from './report-share.service';

/** In-memory control DB for report_shares. */
function fakeControl() {
  const rows: any[] = [];
  const control = {
    reportShare: {
      create: async ({ data }: any) => {
        const r = { createdAt: new Date(), revokedAt: null, ...data };
        rows.push(r);
        return r;
      },
      findUnique: async ({ where }: any) =>
        rows.find((r) => r.id === where.id) ?? null,
      findMany: async ({ where }: any) =>
        rows.filter((r) => r.tenantId === where.tenantId),
      updateMany: async ({ where, data }: any) => {
        const hit = rows.filter(
          (r) =>
            r.id === where.id &&
            r.tenantId === where.tenantId &&
            r.revokedAt === null,
        );
        hit.forEach((r) => Object.assign(r, data));
        return { count: hit.length };
      },
    },
  } as unknown as ControlPrismaService;
  return { control, rows };
}

const totals: ReportCardTotals = {
  from: '2026-10-24T00:00:00.000Z',
  to: '2026-10-30T23:59:59.999Z',
  actions: 1412,
  askedYou: 9,
  blocked: 3,
  secretsKeptSafe: 2,
  series: [1, 2, 3, 4, 5, 6, 7],
};

describe('report shares', () => {
  it('public view exposes exactly the totals keys, even if the row has extras', async () => {
    const { control, rows } = fakeControl();
    const svc = new ReportShareService(control);
    const { shareId } = await svc.create('t1', 'u1', totals);
    expect(shareId).toMatch(/^[A-Za-z0-9_-]{32}$/); // 192 bits
    Object.assign(rows[0].totals, {
      deviceName: 'Work laptop',
      email: 'a@b.c',
      tenantName: 'Acme',
    });
    const view = await svc.publicView(shareId);
    expect(Object.keys(view).sort()).toEqual([
      'actions',
      'askedYou',
      'blocked',
      'from',
      'secretsKeptSafe',
      'series',
      'to',
    ]);
    expect(JSON.stringify(view)).not.toMatch(/laptop|@|Acme/);
  });
  it('a revoked, unknown or malformed id is 404', async () => {
    const { control } = fakeControl();
    const svc = new ReportShareService(control);
    const { shareId } = await svc.create('t1', 'u1', totals);
    await svc.revoke('t1', shareId);
    await expect(svc.publicView(shareId)).rejects.toBeInstanceOf(
      NotFoundException,
    );
    await expect(svc.publicView('x'.repeat(32))).rejects.toBeInstanceOf(
      NotFoundException,
    );
    await expect(svc.publicView('../etc')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
  it('another tenant cannot list or revoke a share', async () => {
    const { control } = fakeControl();
    const svc = new ReportShareService(control);
    const { shareId } = await svc.create('t1', 'u1', totals);
    expect(await svc.list('t2')).toEqual([]);
    await expect(svc.revoke('t2', shareId)).rejects.toBeInstanceOf(
      NotFoundException,
    );
    expect((await svc.publicView(shareId)).actions).toBe(1412);
  });
});

describe('report card aggregate', () => {
  it('maps rows to totals and a 7-day series, oldest first', async () => {
    const client = {
      $queryRaw: async () => [
        { d: 0, t: 'authorization.allowed', n: 10 },
        { d: 6, t: 'authorization.allowed', n: 5 },
        { d: 0, t: 'authorization.pending_approval', n: 2 },
        { d: 1, t: 'authorization.denied', n: 1 },
        { d: 1, t: 'secret.safe', n: 4 },
        { d: 9, t: 'authorization.allowed', n: 99 },
      ],
    } as unknown as TenantPrismaClient;
    const svc = new ReportCardService(
      {} as ControlPrismaService,
      {} as TenantDatabaseManager,
    );
    const c = await svc.compute(client, new Date('2026-10-31T00:00:00Z'));
    expect(c).toMatchObject({
      actions: 18,
      askedYou: 2,
      blocked: 1,
      secretsKeptSafe: 4,
    });
    expect(c.series).toEqual([5, 0, 0, 0, 0, 1, 12]);
  });
});

describe('weekly job schedule', () => {
  it('picks the next Sunday 18:00 UTC', () => {
    expect(
      nextSundayNight(new Date('2026-10-30T10:00:00Z')).toISOString(),
    ).toBe('2026-11-01T18:00:00.000Z');
    expect(
      nextSundayNight(new Date('2026-11-01T19:00:00Z')).toISOString(),
    ).toBe('2026-11-08T18:00:00.000Z');
  });
});
