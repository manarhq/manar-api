import { describe, expect, it, vi } from 'vitest';
import { AiDefaultService } from './ai-default.service';

interface Row {
  id: string;
  kind: 'PERSONAL' | 'COMPANY';
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
  kind: 'PERSONAL',
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
    /** The intent / completion audit write throws for these ids. */
    failIntent?: string[];
    failCompletion?: string[];
    /** Runs between the intent write and the guarded flip (a concurrent change). */
    midRun?: (id: string) => void;
  } = {},
) {
  const readOnly = vi.fn().mockResolvedValue(1);
  const events = new Map<string, { eventType: string; data: any }[]>();
  const control = {
    /** The guarded flip, evaluated the way the SQL does. */
    $executeRaw: vi.fn((_s: TemplateStringsArray, id: string) => {
      const r = rows.find((x) => x.id === id);
      const gov = (opts.government ?? []).includes(id);
      const ok =
        r &&
        !r.allowExternalAi &&
        !r.allowExternalAiChosen &&
        r.sector === 'COMMERCIAL' &&
        r.residency !== 'AIR_GAPPED' &&
        r.status === 'ACTIVE' &&
        !gov;
      if (ok)
        Object.assign(r, {
          allowExternalAi: true,
          aiDefaultNoticePending: true,
        });
      return Promise.resolve(ok ? 1 : 0);
    }),
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
          findMany: ({ where }: { where: { allowExternalAi: boolean } }) =>
            Promise.resolve(
              rows
                .filter(
                  (r) =>
                    r.allowExternalAi === where.allowExternalAi &&
                    (where.allowExternalAi
                      ? !r.allowExternalAiChosen
                      : r.status !== 'DELETED'),
                )
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
              findMany: (args: { where: { eventType: string } }) =>
                Promise.resolve(
                  (events.get(id) ?? []).filter(
                    (e) => e.eventType === args.where.eventType,
                  ),
                ),
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
  const audit = {
    record: vi.fn(
      (
        _c: unknown,
        id: string,
        input: { eventType: string; data: { intentId?: string } },
      ) => {
        if (input.eventType.endsWith('_intent')) {
          if (opts.failIntent?.includes(id))
            return Promise.reject(new Error('audit down'));
          opts.midRun?.(id);
        } else if (
          input.eventType.endsWith('_applied') &&
          opts.failCompletion?.includes(id)
        )
          return Promise.reject(new Error('audit down'));
        events.set(id, [...(events.get(id) ?? []), input]);
        return Promise.resolve({});
      },
    ),
  };
  const config = { get: () => opts.deployment ?? 'hosted' };
  const service = new AiDefaultService(
    control as never,
    tenants as never,
    audit as never,
    config as never,
  );
  return { service, audit, control, readOnly, events };
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

const eventTypes = (audit: { record: { mock: { calls: unknown[][] } } }) =>
  audit.record.mock.calls.map((c) => (c[2] as { eventType: string }).eventType);

describe('ai:default-on', () => {
  it('dry run: counts only (split by kind), changes and records nothing, reads in read-only transactions', async () => {
    const rows = fixture();
    rows.find((r) => r.id === 'old')!.kind = 'COMPANY';
    const before = JSON.stringify(rows);
    const { service, audit, control, readOnly } = setup(rows, {
      explicit: ['explicit-in-log'],
      government: ['gov'],
    });
    const counts = await service.run({ dryRun: true });
    expect(counts).toEqual({
      flip: 2,
      flipPersonal: 1,
      flipEnterprise: 1,
      enterpriseHeld: 0,
      changedMidRun: 0,
      completionFailed: 0,
      reconciled: 0,
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
    expect(control.$executeRaw).not.toHaveBeenCalled();
    expect(audit.record).not.toHaveBeenCalled();
    expect(readOnly).toHaveBeenCalled();
  });

  it('flips personal workspaces; company ones only with --include-enterprise', async () => {
    const rows = fixture();
    rows.find((r) => r.id === 'old')!.kind = 'COMPANY';
    const { service } = setup(rows, {
      explicit: ['explicit-in-log'],
      government: ['gov'],
    });
    const held = await service.run({ dryRun: false });
    expect(held).toMatchObject({
      flip: 1,
      flipPersonal: 1,
      flipEnterprise: 0,
      enterpriseHeld: 1,
    });
    expect(rows.find((r) => r.id === 'old')!.allowExternalAi).toBe(false);
    const all = await service.run({ dryRun: false, includeEnterprise: true });
    expect(all).toMatchObject({ flip: 1, flipEnterprise: 1 });
    expect(rows.find((r) => r.id === 'old')!.allowExternalAi).toBe(true);
  });

  it('flips only old-default workspaces, backfills the explicit ones, intent then completion per flip', async () => {
    const rows = fixture();
    const { service, audit } = setup(rows, {
      explicit: ['explicit-in-log'],
      government: ['gov'],
    });
    const counts = await service.run({
      dryRun: false,
      includeEnterprise: true,
    });
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
    expect(eventTypes(audit)).toEqual([
      'tenant.settings.ai_default_intent',
      'tenant.settings.ai_default_applied',
      'tenant.settings.ai_default_intent',
      'tenant.settings.ai_default_applied',
    ]);
    const done = audit.record.mock.calls[1]![2] as unknown as {
      data: { intentId: string; applied: boolean };
    };
    const intent = audit.record.mock.calls[0]![2] as unknown as {
      data: { intentId: string };
    };
    expect(done.data).toMatchObject({
      intentId: intent.data.intentId,
      applied: true,
    });
  });

  it('is idempotent: a second run changes and records nothing', async () => {
    const rows = fixture();
    const { service, audit } = setup(rows, {
      explicit: ['explicit-in-log'],
      government: ['gov'],
    });
    await service.run({ dryRun: false });
    audit.record.mockClear();
    const again = await service.run({ dryRun: false });
    expect(again.flip).toBe(0);
    expect(audit.record).not.toHaveBeenCalled();
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
    expect(audit.record).not.toHaveBeenCalled();
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
    expect(audit.record).toHaveBeenCalledTimes(2);
  });

  it('unknown sector stays off and the owner is shown the opt-in notice', async () => {
    const rows = [row('unknown', { sector: null })];
    const { service } = setup(rows);
    expect(await service.run({ dryRun: true })).toMatchObject({
      needsReview: 1,
    });
    expect(rows[0]!.aiOptInNoticePending).toBe(false);
    await service.run({ dryRun: false });
    expect(rows[0]).toMatchObject({
      allowExternalAi: false,
      aiOptInNoticePending: true,
    });
  });

  it('an intent that cannot be written changes nothing and is counted failed', async () => {
    const rows = [row('a'), row('b')];
    const { service, audit } = setup(rows, { failIntent: ['a'] });
    const counts = await service.run({ dryRun: false });
    expect(counts).toMatchObject({ flip: 1, failed: 1 });
    expect(rows[0]).toMatchObject({
      allowExternalAi: false,
      aiDefaultNoticePending: false,
    });
    expect(rows[1]!.allowExternalAi).toBe(true);
    // No completion for 'a': nothing happened.
    expect(audit.record.mock.calls.filter((c) => c[1] === 'a')).toHaveLength(1);
  });

  it('a completion that cannot be written is reported (exit 1) and the next run reconciles it from the row', async () => {
    const rows = [row('a')];
    const first = setup(rows, { failCompletion: ['a'] });
    const counts = await first.service.run({ dryRun: false });
    expect(counts).toMatchObject({ flip: 1, completionFailed: 1, failed: 0 });
    expect(rows[0]!.allowExternalAi).toBe(true);

    // Same tenant log, audit healthy again: the stray intent gets its completion.
    const second = setup(rows);
    second.events.set('a', first.events.get('a') ?? []);
    const again = await second.service.run({ dryRun: false });
    expect(again).toMatchObject({ flip: 0, reconciled: 1, failed: 0 });
    const written = second.audit.record.mock.calls.at(-1)![2] as unknown as {
      eventType: string;
      data: { applied: boolean; reconciled: boolean };
    };
    expect(written.eventType).toBe('tenant.settings.ai_default_applied');
    expect(written.data).toMatchObject({ applied: true, reconciled: true });
    // And a third run has nothing left to reconcile.
    second.audit.record.mockClear();
    second.events.set('a', [
      ...(first.events.get('a') ?? []),
      { eventType: written.eventType, data: written.data },
    ]);
    expect((await second.service.run({ dryRun: false })).reconciled).toBe(0);
  });

  it('a sector or choice that changes between the read and the flip stops the flip (guarded update) and the completion says so', async () => {
    const rows = [row('a'), row('b')];
    const { service, audit } = setup(rows, {
      midRun: (id) => {
        if (id === 'a') rows[0]!.sector = 'GOVERNMENT';
        if (id === 'b') rows[1]!.allowExternalAiChosen = true;
      },
    });
    const counts = await service.run({ dryRun: false });
    expect(counts).toMatchObject({ flip: 0, changedMidRun: 2 });
    expect(rows.every((r) => !r.allowExternalAi)).toBe(true);
    const completions = audit.record.mock.calls
      .map(
        (c) =>
          c[2] as unknown as { eventType: string; data: { applied: boolean } },
      )
      .filter((e) => e.eventType.endsWith('_applied'));
    expect(completions.map((e) => e.data.applied)).toEqual([false, false]);
  });
});
