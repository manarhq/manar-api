/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/require-await -- fakes */
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import type { RecordAuditEventInput } from '../audit/audit.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import {
  SAMPLE_TOTALS,
  actionsPerDay,
  generateSampleData,
} from './sample-data.generator';
import { SampleService } from './sample.service';

/** A tenant client that records every create and hands back ids. */
function recordingClient() {
  const writes: Record<string, any[]> = {};
  let n = 0;
  const model = (name: string) =>
    new Proxy(
      {},
      {
        get: (_t, fn: string) => async (arg: any) => {
          (writes[`${name}.${fn}`] ??= []).push(arg);
          return { id: `${name}-${++n}` };
        },
      },
    );
  const tx = new Proxy({}, { get: (_t, name: string) => model(name) });
  const client = {
    $transaction: async (fn: any) => fn(tx),
    host: { count: async () => writes['host.create']?.length ?? 0 },
  } as unknown as TenantPrismaClient;
  return { client, writes };
}

function recordingAudit() {
  const calls: { tenantId: string; events: RecordAuditEventInput[] }[] = [];
  const audit = {
    recordManyInTransaction: vi.fn(
      async (
        _tx: unknown,
        tenantId: string,
        events: RecordAuditEventInput[],
      ) => {
        calls.push({ tenantId, events });
        return () => undefined;
      },
    ),
  } as unknown as AuditService;
  return { audit, calls };
}

describe('sample data generator', () => {
  it('mirrors the mockup numbers and writes only to the sample tenant', async () => {
    const sample = recordingClient();
    const real = recordingClient();
    const a = recordingAudit();
    await generateSampleData(
      sample.client,
      a.audit,
      'sample-tenant',
      'sub-1',
      new Date('2026-10-31T12:00:00Z'),
    );

    expect(sample.writes['host.create']).toHaveLength(2);
    expect(sample.writes['tool.create']).toHaveLength(5);
    const approvals = sample.writes['approvalRequest.create']!;
    expect(approvals).toHaveLength(9);
    expect(approvals.filter((x) => x.data.status === 'PENDING')).toHaveLength(
      1,
    );

    expect(a.calls).toHaveLength(1);
    expect(a.calls[0]!.tenantId).toBe('sample-tenant');
    const ev = a.calls[0]!.events;
    const count = (t: string) => ev.filter((e) => e.eventType === t).length;
    expect(
      count('authorization.allowed') +
        count('authorization.pending_approval') +
        count('authorization.denied'),
    ).toBe(SAMPLE_TOTALS.actions);
    expect(count('authorization.pending_approval')).toBe(9);
    expect(count('authorization.denied')).toBe(3);
    expect(count('secret.touched')).toBe(2);
    // seven days, all in the past
    const times = ev.map((e) => e.timestamp!.getTime());
    expect(Math.max(...times)).toBeLessThan(
      new Date('2026-10-31T12:00:00Z').getTime(),
    );
    expect(Math.min(...times)).toBeGreaterThanOrEqual(
      new Date('2026-10-24T12:00:00Z').getTime(),
    );
    // the real workspace's client was never touched
    expect(Object.keys(real.writes)).toEqual([]);
    expect(JSON.stringify(ev)).not.toMatch(/@|password|secret-value/);
  });

  it('splits actions over seven days exactly', () => {
    const d = actionsPerDay(1412);
    expect(d).toHaveLength(7);
    expect(d.reduce((x, y) => x + y, 0)).toBe(1412);
  });
});

describe('SampleService', () => {
  const setup = (existing: string | null) => {
    const sample = recordingClient();
    const a = recordingAudit();
    const created = vi.fn(async () => ({
      tenantId: 'sample-1',
      status: 'ACTIVE' as const,
    }));
    const svc = new SampleService(
      {
        createWorkspace: created,
        deleteWorkspace: vi.fn(async () => undefined),
      },
      { find: async () => existing },
      {
        getClient: async (id: string) =>
          id === 'sample-1'
            ? sample.client
            : Promise.reject(new Error('wrong tenant')),
      } as unknown as TenantDatabaseManager,
      a.audit,
    );
    return { svc, created, a, sample };
  };

  it('creates once and fills once; a second call does nothing new', async () => {
    const s = setup(null);
    expect(await s.svc.ensure('sub-1')).toEqual({
      tenantId: 'sample-1',
      status: 'ACTIVE',
    });
    expect(s.created).toHaveBeenCalledWith({
      ownerSubject: 'sub-1',
      kind: 'SAMPLE',
      displayName: 'Sample',
    });
    const s2 = setup('sample-1');
    await s2.svc.ensure('sub-1');
    expect(s2.created).not.toHaveBeenCalled();
    await s2.svc.ensure('sub-1');
    expect(s2.a.calls).toHaveLength(1); // already has hosts after the first fill
  });
});
