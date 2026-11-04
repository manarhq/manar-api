import { describe, expect, it, vi } from 'vitest';
import { SecretAlertBus } from './secret-alert-bus';
import { SecretsConflictError, SecretsService } from './secrets.service';
import {
  AccessRequestSchema,
  HostEventsBatchSchema,
  maskHome,
} from './secrets.validation';

const ev = (o: Record<string, unknown> = {}) => ({
  type: 'secret.touched' as const,
  toolId: 'host.cursor',
  process: 'node',
  pathClass: 'aws' as const,
  maskedPath: '/home/alice/.aws/credentials',
  blocked: true,
  at: new Date(Date.now() + 3_600_000),
  ...o,
});

function setup() {
  const created: Array<Array<Record<string, unknown>>> = [];
  const client = {
    secretEvent: {
      createMany: vi.fn(
        ({ data }: { data: Array<Record<string, unknown>> }) => {
          created.push(data);
          return Promise.resolve({ count: data.length });
        },
      ),
    },
  };
  const audit = { recordSafely: vi.fn().mockResolvedValue(undefined) };
  const bus = new SecretAlertBus();
  const alerts: unknown[] = [];
  bus.subscribe((a) => alerts.push(a));
  const service = new SecretsService(audit as never, bus);
  return { client, audit, service, created, alerts };
}

describe('maskHome', () => {
  it('replaces the user name in any home prefix', () => {
    expect(maskHome('/home/alice/.ssh/id')).toBe('~/.ssh/id');
    expect(maskHome('C:\\Users\\Bob\\.aws\\credentials')).toBe(
      '~\\.aws\\credentials',
    );
    expect(maskHome('/Users/z/.kube/config')).toBe('~/.kube/config');
    expect(maskHome('~/.aws/credentials')).toBe('~/.aws/credentials');
    expect(maskHome('/srv/app/.env')).toBe('/srv/app/.env');
  });
});

describe('HostEventsBatchSchema', () => {
  const ok = {
    events: [
      {
        type: 'secret.touched',
        toolId: 'host.cursor',
        at: '2026-11-01T10:00:00Z',
      },
    ],
  };
  it('accepts a valid batch', () => {
    expect(HostEventsBatchSchema.safeParse(ok).success).toBe(true);
  });
  it.each([
    [
      'unknown type',
      { events: [{ type: 'secret.deleted', at: '2026-11-01T10:00:00Z' }] },
    ],
    [
      'unknown field',
      {
        events: [
          { type: 'secret.touched', at: '2026-11-01T10:00:00Z', token: 'x' },
        ],
      },
    ],
    [
      'bad tool id',
      {
        events: [
          {
            type: 'secret.touched',
            toolId: '../x',
            at: '2026-11-01T10:00:00Z',
          },
        ],
      },
    ],
    [
      'control characters',
      {
        events: [
          {
            type: 'secret.touched',
            process: 'a\nb',
            at: '2026-11-01T10:00:00Z',
          },
        ],
      },
    ],
    ['empty batch', { events: [] }],
    ['101 events', { events: Array.from({ length: 101 }, () => ok.events[0]) }],
  ])('rejects %s', (_n, body) => {
    expect(HostEventsBatchSchema.safeParse(body).success).toBe(false);
  });
});

describe('SecretsService.ingest', () => {
  it('masks the path again, clamps a future time, audits and alerts', async () => {
    const { client, audit, service, created, alerts } = setup();
    await service.ingest(client as never, 't1', 'h1', [ev()]);
    expect(created[0]![0]).toMatchObject({
      hostId: 'h1',
      maskedPath: '~/.aws/credentials',
    });
    expect((created[0]![0]!.at as Date).getTime()).toBeLessThan(
      Date.now() + 6 * 60_000,
    );
    expect(audit.recordSafely).toHaveBeenCalledWith(
      client,
      't1',
      expect.objectContaining({
        eventType: 'secret.touched',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        data: expect.objectContaining({
          hostId: 'h1',
          maskedPath: '~/.aws/credentials',
        }),
      }),
    );
    expect(alerts).toEqual([
      expect.objectContaining({
        tenantId: 't1',
        hostId: 'h1',
        toolId: 'host.cursor',
        blocked: true,
      }),
    ]);
  });

  it('stores watcher status without auditing or alerting, and a failing subscriber is harmless', async () => {
    const { client, audit, service, alerts } = setup();
    await service.ingest(client as never, 't1', 'h1', [
      ev({ type: 'secret.watch.unavailable', toolId: undefined }),
    ]);
    expect(audit.recordSafely).not.toHaveBeenCalled();
    expect(alerts).toHaveLength(0);
  });
});

describe('SecretsService.decideAccess', () => {
  it('refuses a request that was already decided', async () => {
    const audit = { recordSafely: vi.fn() };
    const client = {
      secretVaultAccess: {
        findUnique: vi.fn().mockResolvedValue({
          id: 'a',
          hostId: 'h',
          kind: 'aws',
          ref: 'default',
          program: 'aws',
        }),
        updateMany: vi.fn().mockResolvedValue({ count: 0 }),
      },
      host: { findUnique: vi.fn().mockResolvedValue({ ownerSubject: 'x' }) },
    };
    const s = new SecretsService(audit as never, new SecretAlertBus());
    await expect(
      s.decideAccess(
        client as never,
        't',
        { type: 'human', id: 'u' },
        'a',
        'ALLOW_ONCE',
        { subject: 'u', admin: true, company: true, freshSignIn: false },
      ),
    ).rejects.toBeInstanceOf(SecretsConflictError);
    expect(audit.recordSafely).not.toHaveBeenCalled();
  });
});

describe('vault decisions run the approval rights (founder decisions, 3 and 4 Nov 2026)', () => {
  function vault(ownerSubject: string | null) {
    const updates: Record<string, unknown>[] = [];
    const client = {
      secretVaultAccess: {
        findUnique: vi.fn().mockResolvedValue({
          id: 'a',
          hostId: 'h',
          kind: 'aws',
          ref: 'default',
          program: 'aws',
        }),
        updateMany: vi.fn(({ data }: { data: Record<string, unknown> }) => {
          updates.push(data);
          return Promise.resolve({ count: 1 });
        }),
      },
      host: { findUnique: vi.fn().mockResolvedValue({ ownerSubject }) },
      secretEvent: { create: vi.fn().mockResolvedValue({}) },
    };
    const s = new SecretsService(
      { recordSafely: vi.fn() } as never,
      new SecretAlertBus(),
    );
    const decide = (
      decision: 'ALLOW_ONCE' | 'ALLOW_8H' | 'ALLOW_ALWAYS' | 'DENY',
      who: { company: boolean; freshSignIn?: boolean; subject?: string },
    ) =>
      s.decideAccess(
        client as never,
        't',
        { type: 'human', id: 'u' },
        'a',
        decision,
        {
          subject: who.subject ?? 'me',
          admin: true,
          company: who.company,
          freshSignIn: who.freshSignIn ?? false,
        },
      );
    return { decide, updates };
  }
  const status = (e: unknown) => (e as { getStatus(): number }).getStatus();
  const body = (e: unknown) =>
    (e as { getResponse(): Record<string, unknown> }).getResponse();

  it('a company admin cannot release a secret to their own device, not even once: another approver must', async () => {
    const { decide, updates } = vault('me');
    for (const d of ['ALLOW_ONCE', 'ALLOW_8H', 'ALLOW_ALWAYS'] as const) {
      const e: unknown = await decide(d, {
        company: true,
        freshSignIn: true,
      }).catch((x: unknown) => x);
      expect(status(e)).toBe(403);
    }
    await expect(decide('DENY', { company: true })).resolves.toMatchObject({
      status: 'DENY',
    });
    expect(updates).toHaveLength(1);
  });

  it("a company admin may allow someone else's device always, and the grant has no end", async () => {
    const { decide, updates } = vault('someone-else');
    await decide('ALLOW_ALWAYS', { company: true });
    expect(updates[0]).toMatchObject({
      status: 'ALLOW_ALWAYS',
      expiresAt: null,
    });
  });

  it('a personal owner: once or 8 hours after a fresh sign-in, never always', async () => {
    const { decide, updates } = vault('me');
    const stale: unknown = await decide('ALLOW_8H', { company: false }).catch(
      (x: unknown) => x,
    );
    expect(status(stale)).toBe(401);
    expect(body(stale)).toMatchObject({ code: 'reauth_required' });
    const always: unknown = await decide('ALLOW_ALWAYS', {
      company: false,
      freshSignIn: true,
    }).catch((x: unknown) => x);
    expect(status(always)).toBe(403);
    expect(updates).toHaveLength(0);
    const before = Date.now();
    await decide('ALLOW_8H', { company: false, freshSignIn: true });
    const until = (updates[0]!.expiresAt as Date).getTime();
    expect(until - before).toBeGreaterThanOrEqual(8 * 3_600_000 - 1_000);
    expect(until - before).toBeLessThanOrEqual(8 * 3_600_000 + 1_000);
  });

  it("a personal device with no recorded owner is still the owner's own: no always", async () => {
    const { decide } = vault(null);
    const e: unknown = await decide('ALLOW_ALWAYS', {
      company: false,
      freshSignIn: true,
    }).catch((x: unknown) => x);
    expect(status(e)).toBe(403);
  });
});

describe('standing vault grants: listed, withdrawn, and sent to the device', () => {
  it('the device config lists only live, not withdrawn, standing grants', async () => {
    const findMany = vi.fn().mockResolvedValue([
      { id: 'g8', status: 'ALLOW_8H', expiresAt: new Date('2030-01-01') },
      { id: 'ga', status: 'ALLOW_ALWAYS', expiresAt: null },
    ]);
    const s = new SecretsService(
      { recordSafely: vi.fn() } as never,
      new SecretAlertBus(),
    );
    const out = await s.vaultGrants(
      { secretVaultAccess: { findMany } } as never,
      'h',
    );
    expect(out).toEqual([
      { id: 'g8', until: '2030-01-01T00:00:00.000Z' },
      { id: 'ga', until: null },
    ]);
    const where = (
      findMany.mock.calls[0]![0] as { where: Record<string, unknown> }
    ).where;
    expect(where).toMatchObject({ hostId: 'h', withdrawnAt: null });
  });

  it('withdrawing is audited once; a second withdraw changes nothing', async () => {
    const audit = { recordSafely: vi.fn() };
    let withdrawn = false;
    const client = {
      secretVaultAccess: {
        updateMany: vi.fn(() => {
          const count = withdrawn ? 0 : 1;
          withdrawn = true;
          return Promise.resolve({ count });
        }),
        findUnique: vi.fn().mockResolvedValue({
          id: 'g',
          hostId: 'h',
          kind: 'aws',
          ref: 'default',
          program: 'aws',
          status: 'ALLOW_ALWAYS',
        }),
      },
    };
    const s = new SecretsService(audit as never, new SecretAlertBus());
    const actor = { type: 'human' as const, id: 'u' };
    await s.withdrawGrant(client as never, 't', actor, 'g');
    await s.withdrawGrant(client as never, 't', actor, 'g');
    expect(audit.recordSafely).toHaveBeenCalledTimes(1);
    expect(audit.recordSafely.mock.calls[0]![2]).toMatchObject({
      eventType: 'secret.vault.grant_withdrawn',
      data: { hostId: 'h', grantId: 'g' },
    });
  });
});

describe('SecretsService vault state', () => {
  const row = (state: string) => ({ id: 'v', state });
  it('only a REQUESTED entry can become STORED; a failed restore keeps it STORED', async () => {
    const update = vi.fn().mockResolvedValue({});
    const find = vi.fn();
    const client = { secretVault: { findUnique: find, update } };
    const s = new SecretsService(
      { recordSafely: vi.fn() } as never,
      new SecretAlertBus(),
    );
    find.mockResolvedValue(row('STORED'));
    await expect(
      s.report(client as never, 't', 'h', 'aws', 'p', 'STORED'),
    ).rejects.toBeInstanceOf(SecretsConflictError);
    find.mockResolvedValue(row('RESTORE_REQUESTED'));
    expect(
      await s.report(
        client as never,
        't',
        'h',
        'aws',
        'p',
        'FAILED',
        'disk full',
      ),
    ).toEqual({ state: 'STORED' });
    find.mockResolvedValue(row('REQUESTED'));
    expect(
      await s.report(client as never, 't', 'h', 'aws', 'p', 'FAILED'),
    ).toEqual({ state: 'FAILED' });
  });
});

describe('SecretsService rate limit and audit', () => {
  it('refuses a device that sends more than 600 events a minute', async () => {
    const { client, service } = setup();
    const batch = Array.from({ length: 100 }, () => ev());
    for (let i = 0; i < 6; i++)
      await service.ingest(client as never, 't1', 'h1', batch);
    await expect(
      service.ingest(client as never, 't1', 'h1', [ev()]),
    ).rejects.toMatchObject({ status: 429 });
    // another device is not affected
    await expect(
      service.ingest(client as never, 't1', 'h2', [ev()]),
    ).resolves.toEqual({ accepted: 1 });
  });

  it('audits who asked for a restore', async () => {
    const audit = { recordSafely: vi.fn() };
    const client = {
      host: {
        findUnique: vi.fn().mockResolvedValue({ id: 'h', status: 'APPROVED' }),
      },
      secretVault: {
        findUnique: vi.fn().mockResolvedValue({ id: 'v', state: 'STORED' }),
        update: vi
          .fn()
          .mockResolvedValue({ id: 'v', state: 'RESTORE_REQUESTED' }),
      },
    };
    const s = new SecretsService(audit as never, new SecretAlertBus());
    await s.requestRestore(
      client as never,
      't',
      { type: 'human', id: 'u1' },
      'h',
      'aws',
      'default',
    );
    expect(audit.recordSafely).toHaveBeenCalledWith(
      client,
      't',
      expect.objectContaining({
        eventType: 'secret.vault.restore_requested',
        actor: { type: 'human', id: 'u1' },
      }),
    );
  });
});

describe('AccessRequestSchema', () => {
  const ok = {
    kind: 'aws',
    ref: 'default',
    program: 'aws',
    programPath: '/usr/bin/aws',
    programSha: 'a'.repeat(64),
  };
  it('needs the path and a SHA-256 of the binary', () => {
    expect(AccessRequestSchema.safeParse(ok).success).toBe(true);
    expect(
      AccessRequestSchema.safeParse({ ...ok, programSha: 'xyz' }).success,
    ).toBe(false);
    const { programPath, ...noPath } = ok;
    void programPath;
    expect(AccessRequestSchema.safeParse(noPath).success).toBe(false);
  });
});

describe('secret blocking settings', () => {
  const settings = (row: { blockMode: string } | null) => {
    const upsert = vi.fn().mockResolvedValue({});
    const client = {
      secretSettings: {
        findUnique: vi.fn().mockResolvedValue(row),
        upsert,
      },
    };
    return { client, upsert };
  };

  it.each([
    [null, ['secrets.block', 'secrets.vault.ssh']],
    [{ blockMode: 'keys' }, ['secrets.block', 'secrets.vault.ssh']],
    [
      { blockMode: 'all' },
      ['secrets.block', 'secrets.block.all', 'secrets.vault.ssh'],
    ],
    [{ blockMode: 'off' }, ['secrets.vault.ssh']],
  ])('device features for %j', async (row, want) => {
    const { client } = settings(row);
    const { service } = setup();
    expect(await service.features(client as never)).toEqual(want);
  });

  it('changing the mode is audited with the old and new value', async () => {
    const { client, upsert } = settings({ blockMode: 'keys' });
    const { service, audit } = setup();
    await service.setBlockMode(
      client as never,
      't1',
      { type: 'human', id: 'u1' },
      'all',
    );
    expect(upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: { blockMode: 'all', updatedBy: 'u1' },
      }),
    );
    expect(audit.recordSafely).toHaveBeenCalledWith(
      client,
      't1',
      expect.objectContaining({
        eventType: 'secret.settings.changed',
        data: { from: 'keys', to: 'all' },
      }),
    );
  });
});

describe('file access requests (the watcher asks once per program)', () => {
  const body = (o: Record<string, unknown> = {}) => ({
    kind: 'file',
    ref: 'ssh',
    program: 'cursor-agent',
    programPath: '~/.local/share/cursor-agent/cursor-agent',
    programSha: 'a'.repeat(64),
    ...o,
  });
  it('accepts a file class and refuses an unknown one', () => {
    expect(AccessRequestSchema.safeParse(body()).success).toBe(true);
    expect(AccessRequestSchema.safeParse(body({ ref: 'x' })).success).toBe(
      false,
    );
    expect(
      AccessRequestSchema.safeParse(body({ kind: 'aws', ref: 'default' }))
        .success,
    ).toBe(true);
  });
  it('does not need a vault entry and folds a repeated open question', async () => {
    const open = { id: 'a1', status: 'PENDING' };
    const client = {
      secretVault: { findUnique: vi.fn() },
      secretVaultAccess: { findFirst: vi.fn().mockResolvedValue(open) },
    };
    const { service } = setup();
    const r = await service.createAccess(client as never, 'h1', 'file', 'ssh', {
      name: 'cursor-agent',
      path: '~/x',
      sha: 'a'.repeat(64),
    });
    expect(r).toEqual({ id: 'a1', status: 'PENDING' });
    expect(client.secretVault.findUnique).not.toHaveBeenCalled();
  });
  it('an AI tool asking to restore a key is a question without a vault lookup', () => {
    expect(
      AccessRequestSchema.safeParse(body({ kind: 'ssh-restore', ref: '*' }))
        .success,
    ).toBe(true);
  });
  it('a vault secret still needs its entry', async () => {
    const client = {
      secretVault: { findUnique: vi.fn().mockResolvedValue(null) },
    };
    const { service } = setup();
    await expect(
      service.createAccess(client as never, 'h1', 'aws', 'default', {
        name: 'x',
        path: 'x',
        sha: 'a'.repeat(64),
      }),
    ).rejects.toThrow('not in the vault');
  });
});

describe('ssh key offers and device-initiated moves', () => {
  const vaultClient = (row: { id: string; state: string } | null) => ({
    secretVault: {
      findUnique: vi.fn().mockResolvedValue(row),
      create: vi.fn().mockResolvedValue({}),
      update: vi.fn().mockResolvedValue({}),
    },
  });
  it('a detected key is offered, not moved', async () => {
    const c = vaultClient(null);
    const { service } = setup();
    await service.report(
      c as never,
      't',
      'h',
      'ssh',
      'id_ed25519',
      'AVAILABLE',
    );
    expect(c.secretVault.create).toHaveBeenCalledWith({
      data: {
        hostId: 'h',
        kind: 'ssh',
        ref: 'id_ed25519',
        state: 'AVAILABLE',
        requestedBy: 'device',
      },
    });
  });
  it('an offer never disturbs a key that is stored or being moved', async () => {
    const c = vaultClient({ id: 'v1', state: 'STORED' });
    const { service } = setup();
    await service.report(c as never, 't', 'h', 'ssh', 'k', 'AVAILABLE');
    expect(c.secretVault.update).not.toHaveBeenCalled();
    expect(c.secretVault.create).not.toHaveBeenCalled();
  });
  it('the command line can store and restore without a console request', async () => {
    const { service, audit } = setup();
    const none = vaultClient(null);
    expect(
      await service.report(none as never, 't', 'h', 'ssh', 'k', 'STORED'),
    ).toEqual({ state: 'STORED' });
    expect(audit.recordSafely).toHaveBeenCalled();
    const stored = vaultClient({ id: 'v1', state: 'STORED' });
    expect(
      await service.report(stored as never, 't', 'h', 'ssh', 'k', 'RESTORED'),
    ).toEqual({ state: 'RESTORED' });
  });
  it('a restore report for a key never seen is refused', async () => {
    const { service } = setup();
    await expect(
      service.report(
        vaultClient(null) as never,
        't',
        'h',
        'ssh',
        'k',
        'RESTORED',
      ),
    ).rejects.toThrow('No such vault entry');
  });
});
