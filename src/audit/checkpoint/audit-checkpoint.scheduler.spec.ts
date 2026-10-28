import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ControlPrismaService } from '../../database/control-prisma.service';
import type { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import type { AuditCheckpointService } from './audit-checkpoint.service';
import { AuditCheckpointScheduler } from './audit-checkpoint.scheduler';

function setup(
  createCheckpoint: (client: unknown, id: string) => Promise<unknown>,
) {
  const control = {
    tenant: {
      findMany: vi.fn(() => Promise.resolve([{ id: 't1' }, { id: 't2' }])),
    },
  };
  const manager = {
    getClient: vi.fn((id: string) => Promise.resolve({ id })),
  };
  const service = { createCheckpoint: vi.fn(createCheckpoint) };
  const scheduler = new AuditCheckpointScheduler(
    control as unknown as ControlPrismaService,
    manager as unknown as TenantDatabaseManager,
    service as unknown as AuditCheckpointService,
  );
  return { scheduler, control, service };
}

describe('AuditCheckpointScheduler', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('seals every ACTIVE tenant once a second', async () => {
    const { scheduler, control, service } = setup(() => Promise.resolve(null));
    scheduler.onModuleInit();

    await vi.advanceTimersByTimeAsync(1000);
    expect(control.tenant.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { status: 'ACTIVE' } }),
    );
    expect(service.createCheckpoint.mock.calls.map((c) => c[1])).toEqual([
      't1',
      't2',
    ]);

    await vi.advanceTimersByTimeAsync(1000);
    expect(service.createCheckpoint).toHaveBeenCalledTimes(4);
    scheduler.onModuleDestroy();
  });

  it('keeps going after one tenant fails', async () => {
    const { scheduler, service } = setup((_c, id) =>
      id === 't1'
        ? Promise.reject(new Error('OpenBao down'))
        : Promise.resolve(null),
    );
    scheduler.onModuleInit();

    await vi.advanceTimersByTimeAsync(1000);
    expect(service.createCheckpoint.mock.calls.map((c) => c[1])).toEqual([
      't1',
      't2',
    ]);
    scheduler.onModuleDestroy();
  });

  it('never overlaps a slow round with the next one', async () => {
    let release!: () => void;
    const slow = new Promise<null>((r) => (release = () => r(null)));
    const { scheduler, service } = setup(() => slow);
    scheduler.onModuleInit();

    await vi.advanceTimersByTimeAsync(3000);
    expect(service.createCheckpoint).toHaveBeenCalledTimes(1);

    release();
    await vi.advanceTimersByTimeAsync(1000);
    expect(service.createCheckpoint.mock.calls.length).toBeGreaterThan(1);
    scheduler.onModuleDestroy();
  });

  it('stops on shutdown', async () => {
    const { scheduler, service } = setup(() => Promise.resolve(null));
    scheduler.onModuleInit();
    scheduler.onModuleDestroy();

    await vi.advanceTimersByTimeAsync(5000);
    expect(service.createCheckpoint).not.toHaveBeenCalled();
  });
});
