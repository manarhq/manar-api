/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call */
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import {
  FileChangeNotFoundError,
  FileChangeStateError,
  FileChangesService,
  MAX_PER_HOST,
  RETENTION_MS,
} from './file-changes.service';
import { FileChangeBatchSchema } from './file-changes.validation';

const now = new Date('2026-11-01T12:00:00Z');
const rec = (over = {}) => ({
  snapshotId: 'a'.repeat(16),
  tool: 'claude-code',
  path: '/etc/hosts',
  existed: true,
  sizeBytes: 10,
  sha256: 'b'.repeat(64),
  takenAt: now.toISOString(),
  ...over,
});

function setup() {
  const store = {
    createMany: vi.fn().mockResolvedValue({ count: 1 }),
    deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
    findMany: vi.fn().mockResolvedValue([]),
    findFirst: vi.fn(),
    updateMany: vi.fn().mockResolvedValue({ count: 1 }),
  };
  const audit = { record: vi.fn().mockResolvedValue({}) };
  const svc = new FileChangesService(audit as unknown as AuditService);
  const client = { hostFileChange: store } as never;
  return { store, audit, svc, client };
}

describe('FileChangesService', () => {
  it('validates reports strictly (no contents field, bounded batch)', () => {
    expect(FileChangeBatchSchema.safeParse({ changes: [rec()] }).success).toBe(
      true,
    );
    expect(
      FileChangeBatchSchema.safeParse({ changes: [{ ...rec(), content: 'x' }] })
        .success,
    ).toBe(false);
    expect(FileChangeBatchSchema.safeParse({ changes: [] }).success).toBe(
      false,
    );
    expect(
      FileChangeBatchSchema.safeParse({ changes: Array(51).fill(rec()) })
        .success,
    ).toBe(false);
  });

  it('stores reports scoped to the host, with a 7 day expiry', async () => {
    const { svc, store, client } = setup();
    await svc.report(
      client,
      'h1',
      FileChangeBatchSchema.parse({ changes: [rec()] }),
      now,
    );
    const data = store.createMany.mock.calls[0]![0].data[0];
    expect(data.hostId).toBe('h1');
    expect(data.expiresAt.getTime() - data.takenAt.getTime()).toBe(
      RETENTION_MS,
    );
    expect(store.createMany.mock.calls[0]![0].skipDuplicates).toBe(true);
    expect(store.deleteMany.mock.calls[0]![0].where.hostId).toBe('h1');
  });

  it('replaces a clock that is far off and drops what is already expired', async () => {
    const { svc, store, client } = setup();
    const future = new Date(now.getTime() + 3600_000).toISOString();
    const old = new Date(now.getTime() - RETENTION_MS - 1000).toISOString();
    await svc.report(
      client,
      'h1',
      FileChangeBatchSchema.parse({
        changes: [
          rec({ takenAt: future }),
          rec({ snapshotId: 'c'.repeat(16), takenAt: old }),
        ],
      }),
      now,
    );
    const rows = store.createMany.mock.calls[0]![0].data;
    expect(rows.length).toBe(2);
    expect(rows[0].takenAt.getTime()).toBe(now.getTime());
  });

  it('keeps at most MAX_PER_HOST records', async () => {
    const { svc, store, client } = setup();
    store.findMany.mockResolvedValue([{ id: 'x' }]);
    await svc.report(
      client,
      'h1',
      FileChangeBatchSchema.parse({ changes: [rec()] }),
      now,
    );
    expect(store.findMany.mock.calls[0]![0].skip).toBe(MAX_PER_HOST);
    expect(store.deleteMany).toHaveBeenCalledWith({
      where: { id: { in: ['x'] } },
    });
  });

  it('requests a restore only for an unexpired change of that host, and audits it', async () => {
    const { svc, store, audit, client } = setup();
    store.findFirst.mockResolvedValue({
      id: 'c1',
      path: '/etc/hosts',
      restoreStatus: 'NONE',
      expiresAt: new Date(now.getTime() + 1000),
    });
    await svc.requestRestore(
      client,
      't1',
      { type: 'human', id: 'u1' },
      'h1',
      'c1',
      now,
    );
    expect(store.findFirst.mock.calls[0]![0].where).toEqual({
      id: 'c1',
      hostId: 'h1',
    });
    expect(audit.record.mock.calls[0]![2].eventType).toBe(
      'host.file_change.restore_requested',
    );
  });

  it('refuses expired, missing and already-requested changes', async () => {
    const { svc, store, client } = setup();
    const actor = { type: 'human', id: 'u' } as const;
    store.findFirst.mockResolvedValue(null);
    await expect(
      svc.requestRestore(client, 't', actor, 'h', 'c', now),
    ).rejects.toBeInstanceOf(FileChangeNotFoundError);
    store.findFirst.mockResolvedValue({
      expiresAt: new Date(now.getTime() - 1),
      restoreStatus: 'NONE',
    });
    await expect(
      svc.requestRestore(client, 't', actor, 'h', 'c', now),
    ).rejects.toBeInstanceOf(FileChangeNotFoundError);
    store.findFirst.mockResolvedValue({
      expiresAt: new Date(now.getTime() + 1),
      restoreStatus: 'REQUESTED',
    });
    await expect(
      svc.requestRestore(client, 't', actor, 'h', 'c', now),
    ).rejects.toBeInstanceOf(FileChangeStateError);
  });

  it('a device reports a result only for its own pending request', async () => {
    const { svc, store, audit, client } = setup();
    await svc.restoreResult(
      client,
      't',
      'h1',
      'c1',
      { status: 'RESTORED' },
      now,
    );
    expect(store.updateMany.mock.calls[0]![0].where).toEqual({
      id: 'c1',
      hostId: 'h1',
      restoreStatus: 'REQUESTED',
    });
    expect(audit.record.mock.calls[0]![2].eventType).toBe(
      'host.file_change.restored',
    );
    store.updateMany.mockResolvedValue({ count: 0 });
    await expect(
      svc.restoreResult(client, 't', 'h2', 'c1', { status: 'FAILED' }, now),
    ).rejects.toBeInstanceOf(FileChangeNotFoundError);
  });

  it('hands the device only requested restores of its own host', async () => {
    const { svc, store, client } = setup();
    await svc.pendingRestores(client, 'h1', now);
    expect(store.findMany.mock.calls[0]![0].where.hostId).toBe('h1');
    expect(store.findMany.mock.calls[0]![0].where.restoreStatus).toBe(
      'REQUESTED',
    );
  });

  it('keeps the device note on a restore that worked', async () => {
    const { svc, store, client } = setup();
    await svc.restoreResult(
      client,
      't',
      'h1',
      'c1',
      { status: 'RESTORED', note: 'changed after' },
      now,
    );
    expect(store.updateMany.mock.calls[0]![0].data.restoreNote).toBe(
      'changed after',
    );
  });
});
