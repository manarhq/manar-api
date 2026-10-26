import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import {
  AgentTerminatedError,
  CloudAgentOperationError,
  EnrollmentTokenInvalidError,
} from './agents.errors';
import { AgentsService } from './agents.service';
import type { CertificateAuthorityService } from './certificate-authority.service';
import { hashEnrollmentToken } from './enrollment-token.util';

/**
 * Gate 0 R4: a REVOKED or KILLED agent is never issued an enrollment token
 * and never re-enrolled, even with a token issued before the revocation.
 * Hand-rolled fakes; the full flow against OpenBao is
 * test/agent-identity.e2e-spec.ts.
 */

const RAW_TOKEN = 'raw-token';

function setup(status: string, kind = 'WORKLOAD') {
  const agent = {
    id: 'agent-1',
    slug: 'a1',
    identifier: 'agent://acme/a1',
    status,
    kind,
  };
  const tokenRow = {
    id: 'token-1',
    agentId: agent.id,
    tokenHash: hashEnrollmentToken(RAW_TOKEN),
    usedAt: null,
    expiresAt: new Date(Date.now() + 60_000),
    agent,
  };
  const tokensCreated: unknown[] = [];
  const signed: unknown[] = [];
  const audited: { eventType: string; data: Record<string, unknown> }[] = [];
  const client = {
    agent: {
      findUnique: () => Promise.resolve(agent),
      updateMany: ({
        where,
        data,
      }: {
        where: { status: { notIn: string[] } };
        data: { status: string };
      }) => {
        if (!where.status.notIn.includes(agent.status)) {
          agent.status = data.status;
        }
        return Promise.resolve({ count: 1 });
      },
    },
    agentEnrollmentToken: {
      create: (args: unknown) => {
        tokensCreated.push(args);
        return Promise.resolve();
      },
      findUnique: () => Promise.resolve(tokenRow),
      updateMany: () => Promise.resolve({ count: 1 }),
    },
  } as unknown as TenantPrismaClient;
  const certificateAuthority = {
    issueCertificate: (_client: unknown, target: unknown) => {
      signed.push(target);
      return Promise.resolve({ serialNumber: '01' });
    },
  } as unknown as CertificateAuthorityService;
  const auditService = {
    recordSafely: (
      _client: unknown,
      _tenant: string,
      event: { eventType: string; data: Record<string, unknown> },
    ) => {
      audited.push(event);
      return Promise.resolve();
    },
  } as unknown as AuditService;
  const service = new AgentsService(certificateAuthority, auditService);
  return { service, client, agent, tokensCreated, signed, audited };
}

describe('AgentsService terminal states (R4)', () => {
  for (const status of ['REVOKED', 'KILLED']) {
    it(`refuses to issue an enrollment token for a ${status} agent`, async () => {
      const { service, client, tokensCreated } = setup(status);
      await expect(
        service.createEnrollmentToken(client, 'agent-1', 'acme', 'user-1'),
      ).rejects.toBeInstanceOf(AgentTerminatedError);
      expect(tokensCreated).toHaveLength(0);
    });

    it(`refuses enrollment of a ${status} agent with a pre-revocation token, before signing, and audits it`, async () => {
      const { service, client, agent, signed, audited } = setup(status);
      await expect(
        service.enroll(client, 'tenant-1', RAW_TOKEN, 'csr'),
      ).rejects.toEqual(new EnrollmentTokenInvalidError('agent_terminated'));
      expect(signed).toHaveLength(0);
      expect(agent.status).toBe(status);
      expect(audited).toEqual([
        expect.objectContaining({
          eventType: AUDIT_EVENT_TYPES.AGENT_ENROLLMENT_FAILED,
          data: { reason: 'agent_terminated' },
        }),
      ]);
    });
  }

  for (const status of ['PENDING_ENROLLMENT', 'ACTIVE']) {
    it(`still issues a token to and enrolls a ${status} agent`, async () => {
      const { service, client, agent, tokensCreated, signed } = setup(status);
      await service.createEnrollmentToken(client, 'agent-1', 'acme', 'user-1');
      await service.enroll(client, 'tenant-1', RAW_TOKEN, 'csr');
      expect(tokensCreated).toHaveLength(1);
      expect(signed).toHaveLength(1);
      expect(agent.status).toBe('ACTIVE');
    });
  }
});

describe('AgentsService and cloud agents', () => {
  it('never issues an enrollment token to a CLOUD agent', async () => {
    const { service, client, tokensCreated } = setup('ACTIVE', 'CLOUD');
    await expect(
      service.createEnrollmentToken(client, 'agent-1', 'acme', 'user-1'),
    ).rejects.toBeInstanceOf(CloudAgentOperationError);
    expect(tokensCreated).toHaveLength(0);
  });

  it('sends the revocation of a CLOUD agent to /cloud-agents (Keycloak clean-up)', async () => {
    const { service, client, audited } = setup('ACTIVE', 'CLOUD');
    await expect(
      service.revokeAgent(client, 'tenant-1', 'agent-1', 'r', 'user-1'),
    ).rejects.toBeInstanceOf(CloudAgentOperationError);
    expect(audited).toHaveLength(0);
  });
});

describe('AgentsService.verifyEnrollmentToken (edge preflight gate)', () => {
  it('verifies a usable token for the agent it names, without consuming or auditing it', async () => {
    const { service, client, audited } = setup('PENDING_ENROLLMENT');
    await expect(
      service.verifyEnrollmentToken(client, 'tenant-1', RAW_TOKEN, 'a1'),
    ).resolves.toEqual({ agentId: 'agent-1' });
    expect(audited).toEqual([]);
  });

  it('audits a refused token exactly as enroll does (same event, reason and actor)', async () => {
    for (const status of ['REVOKED', 'PENDING_ENROLLMENT']) {
      const viaEdge = setup(status);
      const viaEnroll = setup(status);
      if (status === 'PENDING_ENROLLMENT')
        for (const s of [viaEdge, viaEnroll])
          (
            s.client.agentEnrollmentToken as unknown as {
              findUnique: () => Promise<null>;
            }
          ).findUnique = () => Promise.resolve(null);
      await viaEdge.service.verifyEnrollmentToken(
        viaEdge.client,
        'tenant-1',
        RAW_TOKEN,
        'a1',
      );
      await viaEnroll.service
        .enroll(viaEnroll.client, 'tenant-1', RAW_TOKEN, 'csr')
        .catch(() => undefined);
      expect(viaEdge.audited).toHaveLength(1);
      expect(viaEdge.audited).toEqual(viaEnroll.audited);
      expect(viaEdge.audited[0]!.eventType).toBe(
        AUDIT_EVENT_TYPES.AGENT_ENROLLMENT_FAILED,
      );
    }
  });

  it('refuses a token naming another agent, a terminal agent, an unknown hash', async () => {
    const pending = setup('PENDING_ENROLLMENT');
    await expect(
      pending.service.verifyEnrollmentToken(
        pending.client,
        'tenant-1',
        RAW_TOKEN,
        'other',
      ),
    ).resolves.toBeNull();
    const revoked = setup('REVOKED');
    await expect(
      revoked.service.verifyEnrollmentToken(
        revoked.client,
        'tenant-1',
        RAW_TOKEN,
        'a1',
      ),
    ).resolves.toBeNull();
    const unknown = setup('PENDING_ENROLLMENT');
    (
      unknown.client.agentEnrollmentToken as unknown as {
        findUnique: () => Promise<null>;
      }
    ).findUnique = () => Promise.resolve(null);
    await expect(
      unknown.service.verifyEnrollmentToken(
        unknown.client,
        'tenant-1',
        RAW_TOKEN,
        'a1',
      ),
    ).resolves.toBeNull();
  });
});
