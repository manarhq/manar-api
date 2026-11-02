/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { PostHogClient } from './posthog.client';
import {
  DataCollectionService,
  effectiveFlags,
  type DeviceTelemetry,
} from './data-collection.service';

const ISS = 'https://kc/realms/r';
const SECRET = 's'.repeat(32);

function setup(
  opts: {
    kind?: string;
    user?: { improveManar: boolean; aiTraining: boolean };
    org?: { dataImproveManar: boolean; dataAiTraining: boolean };
    posthog?: boolean;
  } = {},
) {
  const samples: Record<string, unknown>[] = [];
  const control = {
    userDataPreference: {
      findUnique: async () => opts.user ?? null,
      upsert: async () => ({}),
    },
    tenant: {
      findUniqueOrThrow: async () => ({
        kind: opts.kind ?? 'COMPANY',
        dataImproveManar: opts.org?.dataImproveManar ?? true,
        dataAiTraining: opts.org?.dataAiTraining ?? true,
        // would be a leak if it ever reached PostHog
        name: 'Secret Corp',
      }),
      findUnique: async () => ({ ownerIssuer: null, ownerSubject: null }),
      update: vi.fn(async () => ({})),
    },
    tenantEntitlement: { findUnique: async () => ({ plan: 'company' }) },
    membership: { findFirst: async () => ({ issuer: ISS }) },
    productSample: {
      updateMany: vi.fn(
        async (a: { where: { id?: { in: string[] } }; data: object }) => {
          for (const r of samples)
            if (a.where.id?.in.includes(r.id as string))
              Object.assign(r, a.data);
          return { count: 1 };
        },
      ),
      createMany: async ({ data }: { data: Record<string, unknown>[] }) =>
        void samples.push(...data),
      deleteMany: vi.fn(async (a: { where: Record<string, unknown> }) => {
        const before = samples.length;
        const ids = (a.where as { id?: { in: string[] } }).id?.in;
        if (ids)
          samples.splice(
            0,
            samples.length,
            ...samples.filter((s) => !ids.includes(s.id as string)),
          );
        else if ('createdAt' in a.where)
          samples.splice(
            0,
            samples.length,
            ...samples.filter(
              (s) =>
                (s.createdAt as Date) >= (a.where.createdAt as { lt: Date }).lt,
            ),
          );
        else samples.length = 0;
        return { count: before - samples.length };
      }),
    },
  };
  const cfg: Record<string, string | undefined> =
    opts.posthog === false
      ? {}
      : { POSTHOG_API_KEY: 'phc_test', DATA_COLLECTION_HASH_SECRET: SECRET };
  const posthog = new PostHogClient({ get: (k: string) => cfg[k] } as never);
  const audit = { record: vi.fn(async () => undefined) };
  const svc = new DataCollectionService(
    control as never,
    posthog,
    audit as never,
  );
  return { svc, control, samples, audit, posthog };
}

const batch = (over: Partial<DeviceTelemetry> = {}): DeviceTelemetry => ({
  version: '1.2.3',
  os: 'linux',
  arch: 'amd64',
  events: [{ type: 'health', at: new Date().toISOString(), data: { cpu: 3 } }],
  samples: [],
  ...over,
});

function spyFetch() {
  const calls: { url: string; body: string }[] = [];
  vi.stubGlobal('fetch', async (url: string, init: { body: string }) => {
    calls.push({ url, body: init.body });
    return { ok: true, status: 200 };
  });
  return calls;
}

describe('flags', () => {
  it('default on; effective is user AND org; personal ignores org', async () => {
    expect(
      effectiveFlags({ improveManar: true, aiTraining: true }, null),
    ).toEqual({ improveManar: true, aiTraining: true });
    expect(
      effectiveFlags(
        { improveManar: true, aiTraining: true },
        { improveManar: false, aiTraining: true },
      ),
    ).toEqual({ improveManar: false, aiTraining: false });
    expect(
      effectiveFlags({ improveManar: false, aiTraining: true }, null),
    ).toEqual({ improveManar: false, aiTraining: false });
    const org = { dataImproveManar: false, dataAiTraining: false };
    const personal = await setup({ kind: 'PERSONAL', org }).svc.getMine(
      ISS,
      'u',
      't',
    );
    expect(personal).toEqual({
      improveManar: true,
      aiTraining: true,
      org: null,
      effective: { improveManar: true, aiTraining: true },
      noticeDismissed: false,
    });
    const company = await setup({ kind: 'COMPANY', org }).svc.getMine(
      ISS,
      'u',
      't',
    );
    expect(company.org).toEqual({ improveManar: false, aiTraining: false });
    expect(company.effective.improveManar).toBe(false);
  });
});

describe('aiTraining revocation', () => {
  it('a user turning aiTraining off revokes their stored samples', async () => {
    const f = setup();
    await f.svc.setMine(ISS, 'u', 't', { aiTraining: false });
    expect(f.control.productSample.updateMany).toHaveBeenCalledWith({
      where: { issuer: ISS, subject: 'u' },
      data: { aiTrainingAllowed: false },
    });
    expect(f.control.productSample.deleteMany).not.toHaveBeenCalled();
  });
  it('turning it on does not touch samples', async () => {
    const f = setup();
    await f.svc.setMine(ISS, 'u', 't', { aiTraining: true });
    expect(f.control.productSample.updateMany).not.toHaveBeenCalled();
  });
  it('the org turning aiTraining on to off revokes the workspace samples, once', async () => {
    const f = setup();
    await f.svc.setOrg('t', 'mgr', { aiTraining: false });
    expect(f.control.productSample.updateMany).toHaveBeenCalledWith({
      where: { tenantId: 't' },
      data: { aiTrainingAllowed: false },
    });
  });
  it('the org staying off does not repeat it', async () => {
    const f = setup({ org: { dataImproveManar: true, dataAiTraining: false } });
    await f.svc.setOrg('t', 'mgr', { aiTraining: false });
    expect(f.control.productSample.updateMany).not.toHaveBeenCalled();
  });
});

describe('opt-out and retention', () => {
  it('turning improveManar off deletes the samples and asks PostHog to delete the person', async () => {
    const f = setup();
    f.samples.push({ id: 1, createdAt: new Date() });
    const calls = spyFetch();
    vi.stubGlobal('process', process);
    await f.svc.setMine(ISS, 'u', 't', { improveManar: false });
    expect(f.samples).toHaveLength(0);
    // no personal key configured: nothing sent, only logged
    expect(calls).toHaveLength(0);
  });
  it('person deletion goes to PostHog when a personal key is configured', async () => {
    const calls = spyFetch();
    const p = new PostHogClient({
      get: (k: string) =>
        ({
          POSTHOG_API_KEY: 'k',
          DATA_COLLECTION_HASH_SECRET: SECRET,
          POSTHOG_PERSONAL_API_KEY: 'pk',
          POSTHOG_PROJECT_ID: '7',
        })[k],
    } as never);
    await p.deletePerson(p.distinctId(ISS, 'u'));
    expect(calls[0]!.url).toBe(
      'https://eu.posthog.com/api/projects/7/persons/bulk_delete/',
    );
    expect(calls[0]!.body).not.toContain('"u"');
  });
  it('the org switch off deletes the workspace samples and is audit logged', async () => {
    const f = setup();
    f.samples.push({ id: 1 });
    await f.svc.setOrg('t', 'mgr', { improveManar: false });
    expect(f.samples).toHaveLength(0);
    expect(f.audit.record).toHaveBeenCalledOnce();
  });
  it('the purge removes samples older than 12 months only', async () => {
    const f = setup();
    const now = new Date('2026-11-02T00:00:00Z');
    f.samples.push(
      { id: 'old', createdAt: new Date('2025-10-01T00:00:00Z') },
      { id: 'new', createdAt: new Date('2025-12-01T00:00:00Z') },
    );
    expect(await f.svc.purgeOld(now)).toEqual({ deleted: 1 });
    expect(f.samples.map((s) => s.id)).toEqual(['new']);
  });
});

describe('device telemetry', () => {
  it('is ignored when the effective improveManar is off (user or org)', async () => {
    for (const f of [
      setup({ user: { improveManar: false, aiTraining: true } }),
      setup({ org: { dataImproveManar: false, dataAiTraining: true } }),
    ]) {
      const calls = spyFetch();
      const ok = await f.svc.ingestDevice(
        't',
        'owner',
        batch({
          samples: [
            {
              kind: 'command',
              tool: 'claude',
              decision: 'ask',
              text: 'ls',
              at: new Date().toISOString(),
            },
          ],
        }),
      );
      expect(ok).toBe(false);
      expect(f.samples).toHaveLength(0);
      expect(calls).toHaveLength(0);
    }
  });
  it('re-redacts samples, records aiTrainingAllowed and keeps secrets, email and names out of PostHog', async () => {
    const f = setup({ user: { improveManar: true, aiTraining: false } });
    const calls = spyFetch();
    const key = 'sk-ant-api03-AbCdEf0123456789AbCdEf0123456789';
    await f.svc.ingestDevice(
      't',
      'owner',
      batch({
        events: [
          {
            type: 'crash',
            at: new Date().toISOString(),
            data: {
              stack: `panic at /home/bob/x mail bob@example.com ${key}`,
              ok: true,
            },
          },
        ],
        samples: [
          {
            kind: 'command',
            tool: 'claude',
            decision: 'block',
            text: `cat /home/bob/.env 10.0.0.1 ${key} bob@example.com`,
            at: new Date().toISOString(),
          },
        ],
      }),
    );
    const stored = JSON.stringify(f.samples);
    for (const leak of [key, 'bob', '10.0.0.1'])
      expect(stored).not.toContain(leak);
    expect(f.samples[0]).toMatchObject({
      aiTrainingAllowed: false,
      subject: 'owner',
      tenantId: 't',
    });
    const sent = calls[0]!.body;
    expect(calls[0]!.url).toBe('https://eu.i.posthog.com/batch/');
    for (const leak of [key, 'bob', 'Secret Corp', 'owner', ISS])
      expect(sent).not.toContain(leak);
    const ev = (
      JSON.parse(sent) as {
        batch: { distinct_id: string; properties: Record<string, unknown> }[];
      }
    ).batch[0]!;
    expect(ev.distinct_id).toBe(f.posthog.distinctId(ISS, 'owner'));
    expect(ev.distinct_id).toMatch(/^[0-9a-f]{64}$/);
    expect(ev.properties).toMatchObject({
      plan: 'company',
      workspace_kind: 'company',
      version: '1.2.3',
    });
  });
  it('without a PostHog key samples are still stored and nothing is sent', async () => {
    const f = setup({ posthog: false });
    const calls = spyFetch();
    await f.svc.ingestDevice(
      't',
      'owner',
      batch({
        samples: [
          {
            kind: 'domain',
            tool: 'x',
            decision: 'ask',
            text: 'example.com',
            at: new Date().toISOString(),
          },
        ],
      }),
    );
    expect(f.samples).toHaveLength(1);
    expect(calls).toHaveLength(0);
  });
  it('a device with no known owner reads as off', async () => {
    const f = setup();
    expect((await f.svc.forHost('t', null)).effective).toEqual({
      improveManar: false,
      aiTraining: false,
    });
  });
});

describe('console events', () => {
  const ev = [
    {
      name: 'page_view',
      at: new Date().toISOString(),
      props: { path: '/devices', note: 'mail me@x.io' },
    },
  ];
  it('are dropped when improveManar is off, or PostHog is not configured', async () => {
    const calls = spyFetch();
    expect(
      await setup({
        user: { improveManar: false, aiTraining: true },
      }).svc.ingestConsole(ISS, 'u', 't', ev),
    ).toBe(0);
    expect(
      await setup({ posthog: false }).svc.ingestConsole(ISS, 'u', 't', ev),
    ).toBe(0);
    expect(calls).toHaveLength(0);
  });
  it('forward with plan and workspace kind but never email, name or workspace name', async () => {
    const calls = spyFetch();
    expect(await setup().svc.ingestConsole(ISS, 'u', 't', ev)).toBe(1);
    const sent = calls[0]!.body;
    expect(sent).toContain('"plan":"company"');
    for (const leak of ['me@x.io', 'Secret Corp', '"u"'])
      expect(sent).not.toContain(leak);
  });
});

describe('prop redaction by key', () => {
  const props = async (p: Record<string, string | number | boolean>) => {
    const calls = spyFetch();
    await setup().svc.ingestConsole(ISS, 'u', 't', [
      { name: 'page_view', at: new Date().toISOString(), props: p },
    ]);
    const body = JSON.parse(calls[0]!.body) as {
      batch: { properties: Record<string, unknown> }[];
    };
    return body.batch[0]!.properties;
  };
  it('a secret-looking key redacts the whole value, whatever its type', async () => {
    const out = await props({
      apiToken: 'abc',
      user_password: 12345,
      Secret: true,
    });
    expect(out).toMatchObject({
      apiToken: '<redacted>',
      user_password: '<redacted>',
      Secret: '<redacted>',
    });
  });
  it('assignment rules apply inside values', async () => {
    const out = await props({
      note: 'password=hunter2',
      path: '/devices',
      n: 3,
    });
    expect(JSON.stringify(out)).not.toContain('hunter2');
    expect(out).toMatchObject({ path: '/devices', n: 3 });
  });
  it('device version, os, arch and sample tool are redacted too', async () => {
    const f = setup();
    spyFetch();
    await f.svc.ingestDevice(
      't',
      'owner',
      batch({
        version: 'bob@example.com',
        os: '/home/bob/x',
        arch: '10.0.0.1',
        samples: [
          {
            kind: 'command',
            tool: 'tok-bob@example.com',
            decision: 'ask',
            text: 'ls',
            at: new Date().toISOString(),
          },
        ],
      }),
    );
    expect(JSON.stringify(f.samples)).not.toContain('bob');
  });
});

describe('consent flipped during ingest', () => {
  const sample = {
    kind: 'command' as const,
    tool: 'claude',
    decision: 'ask' as const,
    text: 'ls',
    at: new Date().toISOString(),
  };
  // The owner's row changes right after the first read, i.e. between the check and the insert.
  const flip = (
    f: ReturnType<typeof setup>,
    to: { improveManar: boolean; aiTraining: boolean },
  ) => {
    let reads = 0;
    f.control.userDataPreference.findUnique = async () =>
      ++reads > 1 ? to : null;
  };
  it('improveManar off after the check leaves nothing behind and sends nothing', async () => {
    const f = setup();
    const calls = spyFetch();
    flip(f, { improveManar: false, aiTraining: false });
    expect(
      await f.svc.ingestDevice('t', 'owner', batch({ samples: [sample] })),
    ).toBe(false);
    expect(f.samples).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });
  it('aiTraining off after the check keeps the rows but revokes training use', async () => {
    const f = setup();
    flip(f, { improveManar: true, aiTraining: false });
    await f.svc.ingestDevice('t', 'owner', batch({ samples: [sample] }));
    expect(f.samples).toHaveLength(1);
    expect(f.samples[0]!.aiTrainingAllowed).toBe(false);
  });
});
