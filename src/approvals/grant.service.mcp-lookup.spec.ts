import type { ConfigService } from '@nestjs/config';
import { describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { ApprovalRequestService } from './approval-request.service';
import { GrantService } from './grant.service';
import { verifyGrantToken } from './grant-token.util';
import { computeParameterHash } from './parameter-hash.util';

/**
 * ADR-0007: the MCP door finds the approved grant (or the open approval) for
 * exactly this call. Binding is by agent, task, tool, action, resource and
 * parameter hash; anything else must not match.
 */

const SECRET = 'unit-test-grant-signing-secret-0123456789';
const CALL = {
  tenantId: 'tenant-1',
  agentId: 'agent-1',
  taskId: 'task-1',
  toolId: 'microsoft-graph',
  actionId: 'entra.user.disable',
  resource: 'user-1',
  params: { reason: 'compromised', ticket: 7 },
};

function grantServiceOver(findFirst: ReturnType<typeof vi.fn>) {
  const service = new GrantService(
    {} as never,
    {} as never,
    {} as never,
    { get: () => SECRET } as unknown as ConfigService<AppConfig, true>,
    {} as never,
  );
  const tenantClient = {
    authorizationGrant: { findFirst },
  } as unknown as TenantPrismaClient;
  return { service, tenantClient };
}

describe('GrantService.findRedeemableGrantToken (ADR-0007)', () => {
  it('queries only live grants bound to this exact agent, task, tool, action, resource and parameter hash', async () => {
    const findFirst = vi.fn().mockResolvedValue(null);
    const { service, tenantClient } = grantServiceOver(findFirst);

    await expect(
      service.findRedeemableGrantToken(tenantClient, CALL),
    ).resolves.toBeNull();

    const where = (
      findFirst.mock.calls[0]![0] as { where: Record<string, unknown> }
    ).where;
    expect(where).toMatchObject({
      agentId: 'agent-1',
      taskId: 'task-1',
      toolId: 'microsoft-graph',
      actionId: 'entra.user.disable',
      resource: 'user-1',
      parameterHash: computeParameterHash(CALL),
      consumedAt: null,
      revokedAt: null,
      expiresAt: { gt: expect.any(Date) as unknown },
    });
  });

  it('changed parameters produce a different hash, so the approved grant is not found', async () => {
    const findFirst = vi.fn().mockResolvedValue(null);
    const { service, tenantClient } = grantServiceOver(findFirst);

    await service.findRedeemableGrantToken(tenantClient, {
      ...CALL,
      params: { reason: 'compromised', ticket: 8 },
    });

    const where = (
      findFirst.mock.calls[0]![0] as { where: { parameterHash: string } }
    ).where;
    expect(where.parameterHash).not.toBe(computeParameterHash(CALL));
  });

  it('a found grant comes back as its signed token, bound to the same claims', async () => {
    const now = Date.now();
    const findFirst = vi.fn().mockResolvedValue({
      id: 'grant-1',
      agentId: 'agent-1',
      taskId: 'task-1',
      toolId: 'microsoft-graph',
      actionId: 'entra.user.disable',
      resource: 'user-1',
      parameterHash: computeParameterHash(CALL),
      issuedAt: new Date(now),
      expiresAt: new Date(now + 300_000),
    });
    const { service, tenantClient } = grantServiceOver(findFirst);

    const token = await service.findRedeemableGrantToken(tenantClient, CALL);

    const claims = await verifyGrantToken(token!, SECRET);
    expect(claims).toMatchObject({
      jti: 'grant-1',
      tenantId: 'tenant-1',
      agentId: 'agent-1',
      taskId: 'task-1',
      parameterHash: computeParameterHash(CALL),
    });
  });
});

describe('ApprovalRequestService.findPendingMatch (ADR-0007)', () => {
  function over(rows: { id: string; params: unknown }[]) {
    const findMany = vi.fn().mockResolvedValue(rows);
    const tenantClient = {
      approvalRequest: { findMany },
    } as unknown as TenantPrismaClient;
    return { findMany, tenantClient };
  }

  it('matches the open request with the same parameters, whatever their key order', async () => {
    const { findMany, tenantClient } = over([
      { id: 'other-params', params: { reason: 'compromised', ticket: 8 } },
      { id: 'same', params: { ticket: 7, reason: 'compromised' } },
    ]);

    await expect(
      new ApprovalRequestService().findPendingMatch(tenantClient, CALL),
    ).resolves.toEqual({ id: 'same' });
    expect(
      (findMany.mock.calls[0]![0] as { where: Record<string, unknown> }).where,
    ).toMatchObject({
      taskId: 'task-1',
      agentId: 'agent-1',
      toolId: 'microsoft-graph',
      actionId: 'entra.user.disable',
      resource: 'user-1',
      status: 'PENDING',
      expiresAt: { gt: expect.any(Date) as unknown },
    });
  });

  it('no open request with these parameters: null, so a new approval is opened', async () => {
    const { tenantClient } = over([
      { id: 'other-params', params: { reason: 'compromised', ticket: 8 } },
    ]);

    await expect(
      new ApprovalRequestService().findPendingMatch(tenantClient, CALL),
    ).resolves.toBeNull();
  });
});
