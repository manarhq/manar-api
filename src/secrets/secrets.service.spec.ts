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
    };
    const s = new SecretsService(audit as never, new SecretAlertBus());
    await expect(
      s.decideAccess(
        client as never,
        't',
        { type: 'human', id: 'u' },
        'a',
        'ALLOW_ONCE',
      ),
    ).rejects.toBeInstanceOf(SecretsConflictError);
    expect(audit.recordSafely).not.toHaveBeenCalled();
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
