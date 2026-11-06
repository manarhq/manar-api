import { describe, expect, it, vi } from 'vitest';
import { TenantSectorService } from './tenant-sector.service';

function setup(auditFails = false) {
  const update = vi.fn().mockResolvedValue({});
  const record = vi.fn(() =>
    auditFails ? Promise.reject(new Error('audit down')) : Promise.resolve({}),
  );
  const service = new TenantSectorService(
    { tenant: { update } } as never,
    { getClient: () => Promise.resolve({}) } as never,
    { record } as never,
  );
  return { service, update, record };
}

describe('TenantSectorService', () => {
  it('audits first, then sets the sector; Government is AI off and a recorded choice', async () => {
    const { service, update, record } = setup();
    await service.set('t', 'GOVERNMENT', 'cli');
    expect(record.mock.invocationCallOrder[0]!).toBeLessThan(
      update.mock.invocationCallOrder[0]!,
    );
    expect(update.mock.calls[0]![0]).toMatchObject({
      data: {
        sector: 'GOVERNMENT',
        allowExternalAi: false,
        allowExternalAiChosen: true,
      },
    });
    await service.set('t', 'COMMERCIAL', 'cli');
    expect((update.mock.calls[1]![0] as { data: unknown }).data).toEqual({
      sector: 'COMMERCIAL',
    });
  });

  it('changes nothing when the audit event cannot be written', async () => {
    const { service, update } = setup(true);
    await expect(service.set('t', 'COMMERCIAL', 'cli')).rejects.toThrow();
    expect(update).not.toHaveBeenCalled();
  });
});
