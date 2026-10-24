import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { ControlPrismaService } from '../../database/control-prisma.service';
import type { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { AuditVerifyCommand } from './audit-verify.command';

function command(results: Record<string, { valid: boolean }>) {
  const control = {
    tenant: {
      findMany: vi
        .fn()
        .mockResolvedValue(Object.keys(results).map((id) => ({ id }))),
    },
  } as unknown as ControlPrismaService;
  const manager = {
    getClient: vi.fn((id: string) =>
      Promise.resolve({ id, auditEvent: { count: () => Promise.resolve(3) } }),
    ),
  } as unknown as TenantDatabaseManager;
  const audit = {
    verifyAuditChain: vi.fn((client: { id: string }) =>
      Promise.resolve(
        results[client.id]?.valid
          ? { valid: true }
          : { valid: false, brokenAt: 'event-2' },
      ),
    ),
  } as unknown as AuditService;
  return new AuditVerifyCommand(control, manager, audit);
}

describe('audit:verify', () => {
  afterEach(() => {
    process.exitCode = 0;
  });

  it('exits 0 when every chain is valid', async () => {
    await command({ a: { valid: true }, b: { valid: true } }).run([], {});
    expect(process.exitCode).toBe(0);
  });

  it('exits 1 when any chain is broken (a restore drill must fail loudly)', async () => {
    await command({ a: { valid: true }, b: { valid: false } }).run([], {});
    expect(process.exitCode).toBe(1);
  });

  it('exits 1 when there is nothing to verify (an empty restore is not a pass)', async () => {
    await command({}).run([], {});
    expect(process.exitCode).toBe(1);
  });
});
