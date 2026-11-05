import { describe, expect, it, vi } from 'vitest';
import { AiDefaultService } from './ai-default.service';

interface Row {
  id: string;
  status: string;
  residency: string;
  sector: 'COMMERCIAL' | 'GOVERNMENT' | null;
  allowExternalAi: boolean;
  allowExternalAiChosen: boolean;
  aiDefaultNoticePending: boolean;
  aiOptInNoticePending: boolean;
  createdAt: Date;
}
const row = (id: string, extra: Partial<Row> = {}): Row => ({
  id,
  status: 'ACTIVE',
  residency: 'UAE',
  sector: 'COMMERCIAL',
  allowExternalAi: false,
  allowExternalAiChosen: false,
  aiDefaultNoticePending: false,
  aiOptInNoticePending: false,
  createdAt: new Date('2026-10-01T00:00:00Z'),
  ...extra,
});

/** In-memory control DB and tenant logs; `explicit` ids have a settings update touching allowExternalAi on record. */
function setup(
  rows: Row[],
  opts: {
    explicit?: string[];
    government?: string[];
    broken?: string[];
    deployment?: string;
    pruned?: string[];
    lateStart?: string[];
  } = {},
) {
  const readOnly = vi.fn().mockResolvedValue(1);
  const control = {
    $transaction: (fn: (tx: unknown) => unknown) =>
      fn({
        $executeRaw: readOnly,
        enterpriseProfile: {
          findMany: () =>
            Promise.resolve(
              (opts.government ?? []).map((tenantId) => ({ tenantId })),
            ),
        },
        tenant: {
          findMany: () =>
            Promise.resolve(
              rows
                .filter((r) => !r.allowExternalAi && r.status !== 'DELETED')
                .map((r) => ({ ...r })),
            ),
        },
      }),
    tenant: {
      updateMany: vi.fn(
        ({ where, data }: { where: Partial<Row>; data: Partial<Row> }) => {
          const r = rows.find(
            (x) =>
              x.id === where.id &&
              (where.allowExternalAi === undefined ||
                x.allowExternalAi === where.allowExternalAi) &&
              (where.allowExternalAiChosen === undefined ||
                x.allowExternalAiChosen === where.allowExternalAiChosen),
          );
          if (r) Object.assign(r, data);
          return Promise.resolve({ count: r ? 1 : 0 });
        },
      ),
    },
  };
  const tenants = {
    getClient: (id: string) => {
      if (opts.broken?.includes(id))
        return Promise.reject(new Error('db down'));
      return Promise.resolve({
        $transaction: (fn: (tx: unknown) => unknown) =>
          fn({
            $executeRaw: readOnly,
            auditEvent: {
              findFirst: (args: { where?: object }) => {
                if (args.where) {
                  return Promise.resolve(
                    opts.explicit?.includes(id) ? { id: 'e' } : null,
                  );
                }
                const created = rows.find((r) => r.id === id)!.createdAt;
                const day = 24 * 3_600_000;
                const late = opts.lateStart?.includes(id);
                return Promise.resolve({
                  timestamp: new Date(
                    created.getTime() + (late ? 30 * day : 1000),
                  ),
                });
              },
            },
            auditChainAnchor: {
              count: () => Promise.resolve(opts.pruned?.includes(id) ? 1 : 0),
            },
          }),
        id,
      });
    },
  };
  const audit = { recordSafely: vi.fn().mockResolvedValue(undefined) };
  const config = { get: () => opts.deployment ?? 'hosted' };
  const service = new AiDefaultService(
    control as never,
    tenants as never,
    audit as never,
    config as never,
  );
  return { service, audit, control, readOnly };
}

const fixture = () => [
  row('old'),
  row('personal'),
  row('chosen-off', { allowExternalAiChosen: true }),
  row('explicit-in-log'),
  row('air', { residency: 'AIR_GAPPED' }),
  row('gov'),
  // Government by its own recorded sector, with no enterprise profile.
  row('gov-no-profile', { sector: 'GOVERNMENT' }),
  // Sector not known: needs review, never flipped.
  row('unknown', { sector: null }),
  row('queued', { status: 'QUEUED' }),
  row('on', { allowExternalAi: true }),
];

describe('ai:default-on', () => {
  it('dry run: counts only, changes and records nothing, reads in read-only transactions', async () => {
    const rows = fixture();
    const before = JSON.stringify(rows);
    const { service, audit, control, readOnly } = setup(rows, {
      explicit: ['explicit-in-log'],
      government: ['gov'],
    });
    const counts = await service.run({ dryRun: true });
    expect(counts).toEqual({
      flip: 2,
      keptExplicit: 2,
      skippedGovernment: 2,
      skippedCustomerDeployment: 0,
      needsReview: 1,
      historyIncomplete: 0,
      skippedAirGapped: 1,
      skippedNotActive: 1,
      failed: 0,
    });
    expect(JSON.stringify(rows)).toBe(before);
    expect(control.tenant.updateMany).not.toHaveBeenCalled();
    expect(audit.recordSafely).not.toHaveBeenCalled();
    expect(readOnly).toHaveBeenCalled();
  });

  it('flips only old-default workspaces, backfills the explicit ones, one audit event per flip', async () => {
    const rows = fixture();
    const { service, audit } = setup(rows, {
      explicit: ['explicit-in-log'],
      government: ['gov'],
    });
    const counts = await service.run({ dryRun: false });
    expect(counts.flip).toBe(2);
    const by = (id: string) => rows.find((r) => r.id === id)!;
    expect(by('old')).toMatchObject({
      allowExternalAi: true,
      aiDefaultNoticePending: true,
    });
    expect(by('personal').allowExternalAi).toBe(true);
    // Owner's own choices stay off; the log-only one is now recorded as chosen.
    expect(by('chosen-off').allowExternalAi).toBe(false);
    expect(by('explicit-in-log')).toMatchObject({
      allowExternalAi: false,
      allowExternalAiChosen: true,
    });
    expect(by('air').allowExternalAi).toBe(false);
    expect(by('gov').allowExternalAi).toBe(false);
    expect(by('gov-no-profile').allowExternalAi).toBe(false);
    expect(by('unknown').allowExternalAi).toBe(false);
    expect(by('queued').allowExternalAi).toBe(false);
    expect(audit.recordSafely).toHaveBeenCalledTimes(2);
    expect(audit.recordSafely.mock.calls[0]![2]).toMatchObject({
      eventType: 'tenant.settings.ai_default_applied',
    });
  });

  it('is idempotent: a second run changes and records nothing', async () => {
    const rows = fixture();
    const { service, audit } = setup(rows, {
      explicit: ['explicit-in-log'],
      government: ['gov'],
    });
    await service.run({ dryRun: false });
    audit.recordSafely.mockClear();
    const again = await service.run({ dryRun: false });
    expect(again.flip).toBe(0);
    expect(audit.recordSafely).not.toHaveBeenCalled();
  });

  it('an unreadable audit log is never treated as "no choice": the workspace is left alone and counted failed', async () => {
    const rows = [row('a'), row('b')];
    const { service } = setup(rows, { broken: ['a'] });
    const counts = await service.run({ dryRun: false });
    expect(counts).toMatchObject({ flip: 1, failed: 1 });
    expect(rows[0]!.allowExternalAi).toBe(false);
    expect(rows[1]!.allowExternalAi).toBe(true);
  });

  it('a customer-hosted deployment is never flipped', async () => {
    const rows = [row('a'), row('b')];
    const { service, audit } = setup(rows, { deployment: 'customer' });
    const counts = await service.run({ dryRun: false });
    expect(counts).toMatchObject({ flip: 0, skippedCustomerDeployment: 2 });
    expect(rows.every((r) => !r.allowExternalAi)).toBe(true);
    expect(audit.recordSafely).not.toHaveBeenCalled();
  });

  it('a pruned or late-starting history proves nothing: no flip, counted, and the owner gets an opt-in notice', async () => {
    const rows = [row('pruned'), row('late'), row('whole')];
    const { service, audit } = setup(rows, {
      pruned: ['pruned'],
      lateStart: ['late'],
    });
    const dry = await service.run({ dryRun: true });
    expect(dry).toMatchObject({ flip: 1, historyIncomplete: 2 });
    expect(rows.every((r) => !r.aiOptInNoticePending)).toBe(true);

    await service.run({ dryRun: false });
    expect(rows.map((r) => r.allowExternalAi)).toEqual([false, false, true]);
    expect(rows.map((r) => r.aiOptInNoticePending)).toEqual([
      true,
      true,
      false,
    ]);
    expect(audit.recordSafely).toHaveBeenCalledTimes(1);
  });
});
