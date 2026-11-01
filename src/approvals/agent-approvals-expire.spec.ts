import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { AgentApprovalsController } from './agent-approvals.controller';

function build(opts: { owner?: string; paused?: boolean; status?: string }) {
  const row = {
    id: 'ap1',
    agentId: opts.owner ?? 'ag1',
    status: opts.status ?? 'PENDING',
    toolId: 'host.claude-code',
    actionId: 'bash',
    grant: null,
  };
  const client = {
    workspacePause: {
      findUnique: () => Promise.resolve(opts.paused ? { paused: true } : null),
    },
  };
  const svc = {
    getOrThrow: vi.fn(() => Promise.resolve(row)),
    expireIfPending: vi.fn(() =>
      Promise.resolve(
        row.status === 'PENDING'
          ? { expired: true, status: 'EXPIRED' }
          : { expired: false, status: row.status },
      ),
    ),
  };
  const audit = {
    recordSafely: vi.fn<(c: unknown, t: string, e: object) => Promise<boolean>>(
      () => Promise.resolve(true),
    ),
  };
  const c = new AgentApprovalsController(
    svc as never,
    {} as never,
    { getClient: () => Promise.resolve(client) } as never,
    audit as never,
  );
  const agent = { tenant: { id: 't1' }, agent: { id: 'ag1' } } as never;
  return { c, svc, audit, agent };
}

describe('agent approvals', () => {
  it('the hook can expire its own pending approval once, and it is logged as no_answer', async () => {
    const { c, audit, agent } = build({});
    expect(await c.expire(agent, 'ap1')).toEqual({
      id: 'ap1',
      status: 'EXPIRED',
    });
    expect(audit.recordSafely.mock.calls[0]?.[2]).toMatchObject({
      eventType: 'approval.expired',
      data: { reason: 'no_answer' },
    });
  });

  it("cannot expire another agent's approval or an already decided one", async () => {
    await expect(
      build({ owner: 'other' }).c.expire(build({}).agent, 'ap1'),
    ).rejects.toBeInstanceOf(NotFoundException);
    const done = build({ status: 'APPROVED' });
    expect(await done.c.expire(done.agent, 'ap1')).toEqual({
      id: 'ap1',
      status: 'APPROVED',
    });
    expect(done.audit.recordSafely).not.toHaveBeenCalled();
  });

  it('an approval that landed during a pause is reported as PAUSED, with no grant token', async () => {
    const { c, agent } = build({ status: 'APPROVED', paused: true });
    expect(await c.get(agent, 'ap1')).toMatchObject({ status: 'PAUSED' });
  });
});
