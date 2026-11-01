/* eslint-disable @typescript-eslint/no-unsafe-assignment -- expect.objectContaining matchers */
import { describe, expect, it } from 'vitest';
import { makeDecisionHarness } from './decision-pipeline.fakes';

const REQUEST = {
  taskId: 'task-1',
  toolId: 'host.cursor',
  actionId: 'file.read',
  resource: '/home/u/.aws/credentials',
};
const GRANT = { id: 'grant-1', expiresAt: new Date(Date.now() + 3_600_000) };
const needsApproval = {
  effect: 'APPROVAL_REQUIRED' as const,
  policyId: 'p',
  policyVersionId: 'pv',
};

describe('8-hour allow grants in the decision path (spec 4.6)', () => {
  it('without a grant the request still needs approval', async () => {
    const h = makeDecisionHarness({ policy: needsApproval });
    const r = await h.service.authorize(
      h.tenantClient,
      't1',
      'agent-1',
      REQUEST,
    );
    expect(r.decision).toBe('APPROVAL_REQUIRED');
  });

  it('a live grant satisfies a policy approval requirement and is audited as used', async () => {
    const h = makeDecisionHarness({ policy: needsApproval, allowGrant: GRANT });
    const r = await h.service.authorize(
      h.tenantClient,
      't1',
      'agent-1',
      REQUEST,
    );
    expect(r.decision).toBe('ALLOW');
    expect(h.recordSafely).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({
        eventType: 'approval.grant.used',
        data: expect.objectContaining({
          grantId: 'grant-1',
          toolId: 'host.cursor',
        }),
      }),
    );
  });

  it('a live grant also covers the risk ceiling', async () => {
    const h = makeDecisionHarness({ riskScore: 90, allowGrant: GRANT });
    const r = await h.service.authorize(
      h.tenantClient,
      't1',
      'agent-1',
      REQUEST,
    );
    expect(r.decision).toBe('ALLOW');
  });

  it('never overrides a policy DENY, OpenFGA or a kill switch', async () => {
    const deny = makeDecisionHarness({
      policy: { effect: 'DENY', policyId: 'p', policyVersionId: 'pv' },
      allowGrant: GRANT,
    });
    expect(
      (
        await deny.service.authorize(
          deny.tenantClient,
          't1',
          'agent-1',
          REQUEST,
        )
      ).decision,
    ).toBe('DENY');
    const fga = makeDecisionHarness({
      openFgaAllowed: false,
      policy: needsApproval,
      allowGrant: GRANT,
    });
    expect(
      (await fga.service.authorize(fga.tenantClient, 't1', 'agent-1', REQUEST))
        .decision,
    ).toBe('DENY');
    const ks = makeDecisionHarness({
      killSwitch: {
        killed: true,
        reason: 'tenant_killed',
        scope: 'TENANT',
      } as never,
      policy: needsApproval,
      allowGrant: GRANT,
    });
    expect(
      (await ks.service.authorize(ks.tenantClient, 't1', 'agent-1', REQUEST))
        .decision,
    ).toBe('DENY');
  });

  it('looks the grant up by device when the host path sets hostId, else by agent', async () => {
    const host = makeDecisionHarness({ policy: needsApproval });
    await host.service.authorize(host.tenantClient, 't1', 'agent-1', REQUEST, {
      channel: 'AUTHORIZE',
      hostId: 'h1',
    });
    expect(host.client.approvalAllowGrant.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          hostId: 'h1',
          resource: REQUEST.resource,
        }),
      }),
    );
    const agent = makeDecisionHarness({ policy: needsApproval });
    await agent.service.authorize(agent.tenantClient, 't1', 'agent-1', REQUEST);
    const where = (
      agent.client.approvalAllowGrant.findFirst.mock.calls as unknown as [
        { where: object },
      ][]
    )[0]![0].where;
    expect(where).toMatchObject({ agentId: 'agent-1' });
    expect(where).not.toHaveProperty('hostId');
  });

  it('a failing grant lookup fails closed', async () => {
    const h = makeDecisionHarness({ policy: needsApproval });
    h.client.approvalAllowGrant.findFirst.mockRejectedValueOnce(
      new Error('db down'),
    );
    const r = await h.service.authorize(
      h.tenantClient,
      't1',
      'agent-1',
      REQUEST,
    );
    expect(r).toMatchObject({
      decision: 'DENY',
      reason: 'enforcement_dependency_unavailable',
    });
  });
});
