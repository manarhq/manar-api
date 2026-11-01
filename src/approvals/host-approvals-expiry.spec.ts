import { describe, expect, it, vi } from 'vitest';
import {
  HOST_APPROVAL_TTL_MS,
  HostApprovalsService,
} from './host-approvals.service';

describe('device approvals with no answer', () => {
  it('live for two minutes', () => {
    expect(HOST_APPROVAL_TTL_MS).toBe(120_000);
  });

  it('are denied once, logged once, with reason no_answer', async () => {
    const now = new Date('2026-11-01T10:00:00Z');
    const due = [
      { id: 'a1', hostId: 'h1', toolId: 'host.cursor', actionId: 'edit' },
    ];
    let first = true;
    const client = {
      hostApproval: {
        findMany: vi.fn<(a: { where: object }) => Promise<typeof due>>(() =>
          Promise.resolve(due),
        ),
        // a second reader loses the race: no second event
        updateMany: vi.fn(() =>
          Promise.resolve({ count: first ? ((first = false), 1) : 0 }),
        ),
      },
    };
    const audit = {
      recordSafely: vi.fn<
        (c: unknown, t: string, e: object) => Promise<boolean>
      >(() => Promise.resolve(true)),
    };
    const svc = new HostApprovalsService(audit as any, {} as any);
    expect(await svc.expireDue(client as any, 't1', now)).toBe(1);
    expect(await svc.expireDue(client as any, 't1', now)).toBe(0);
    expect(audit.recordSafely).toHaveBeenCalledTimes(1);
    expect(audit.recordSafely.mock.calls[0]?.[2]).toMatchObject({
      eventType: 'approval.expired',
      data: { reason: 'no_answer', hostApprovalId: 'a1' },
    });
    expect(client.hostApproval.findMany.mock.calls[0]?.[0]?.where).toEqual({
      status: 'PENDING',
      expiresAt: { lte: now },
    });
  });
});
