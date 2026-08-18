import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { buildAgentIdentifier } from './agent-identifier';
import {
  AgentNotFoundError,
  EnrollmentTokenInvalidError,
} from './agents.errors';
import {
  CertificateAuthorityService,
  IssuedCertificate,
} from './certificate-authority.service';
import {
  generateEnrollmentToken,
  hashEnrollmentToken,
} from './enrollment-token.util';

export interface CreateAgentInput {
  slug: string;
  displayName: string;
  tenantSlug: string;
  createdBy: string;
}

export interface CreatedEnrollmentToken {
  /** The raw token — returned exactly once, never retrievable again (matches `AgentEnrollmentToken.tokenHash`'s doc comment). */
  rawToken: string;
  expiresAt: Date;
}

/**
 * Orchestrates the human-facing agent lifecycle (create → issue enrollment
 * token → revoke) and the agent-facing enrollment exchange (Section 14).
 * `CertificateAuthorityService` is where the actual PKI/CSR-validation
 * policy lives; this service is the surrounding business logic —
 * agent/token bookkeeping — that both the human-facing `/agents`
 * controller and the agent-facing `/agents/enroll` controller share.
 */
@Injectable()
export class AgentsService {
  private readonly logger = new Logger(AgentsService.name);

  /**
   * Short (Section 14: "e.g. 15 minutes") — an enrollment token is a
   * bearer credential for "become this specific pending agent," so its
   * exposure window (in transit to wherever the agent process reads it
   * from) should be short.
   */
  static readonly ENROLLMENT_TOKEN_TTL_MS = 15 * 60 * 1000;

  constructor(
    private readonly certificateAuthority: CertificateAuthorityService,
    private readonly auditService: AuditService,
  ) {}

  async createAgent(tenantClient: TenantPrismaClient, input: CreateAgentInput) {
    const identifier = buildAgentIdentifier(input.tenantSlug, input.slug);
    return tenantClient.agent.create({
      data: {
        slug: input.slug,
        identifier,
        displayName: input.displayName,
        createdBy: input.createdBy,
      },
    });
  }

  async createEnrollmentToken(
    tenantClient: TenantPrismaClient,
    agentId: string,
    tenantSlug: string,
    createdBy: string,
  ): Promise<CreatedEnrollmentToken> {
    const agent = await tenantClient.agent.findUnique({
      where: { id: agentId },
    });
    if (!agent) throw new AgentNotFoundError(agentId);

    const rawToken = generateEnrollmentToken({
      tenantSlug,
      agentSlug: agent.slug,
    });
    const tokenHash = hashEnrollmentToken(rawToken);
    const expiresAt = new Date(
      Date.now() + AgentsService.ENROLLMENT_TOKEN_TTL_MS,
    );

    await tenantClient.agentEnrollmentToken.create({
      data: { agentId, tokenHash, expiresAt, createdBy },
    });

    return { rawToken, expiresAt };
  }

  /**
   * The agent-facing enrollment exchange: `{ token, csr }` in, an issued
   * certificate out. Looks the token up by hash (never by raw value — see
   * enrollment-token.util.ts), and "claims" it (an atomic
   * `usedAt: null → now` update) *before* calling
   * `CertificateAuthorityService`, not after. This ordering is deliberate:
   *
   *   - It closes the race between two concurrent requests presenting the
   *     same still-valid token (only one `updateMany` can match
   *     `usedAt: null`).
   *   - It means single-use is enforced even if certificate issuance
   *     itself fails partway through — the token is burned either way, so
   *     an interrupted enrollment fails closed (the agent stays
   *     `PENDING_ENROLLMENT`, requiring a human to issue a fresh token)
   *     rather than risking two certificates from one token.
   */
  async enroll(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    rawToken: string,
    csrPem: string,
  ): Promise<IssuedCertificate> {
    const tokenHash = hashEnrollmentToken(rawToken);
    const tokenRow = await tenantClient.agentEnrollmentToken.findUnique({
      where: { tokenHash },
      include: { agent: true },
    });

    if (!tokenRow) {
      await this.recordEnrollmentFailure(tenantClient, tenantId, 'not_found');
      throw new EnrollmentTokenInvalidError('not_found');
    }
    if (tokenRow.usedAt) {
      await this.recordEnrollmentFailure(
        tenantClient,
        tenantId,
        'used',
        tokenRow.agentId,
      );
      throw new EnrollmentTokenInvalidError('used');
    }
    if (tokenRow.expiresAt.getTime() < Date.now()) {
      await this.recordEnrollmentFailure(
        tenantClient,
        tenantId,
        'expired',
        tokenRow.agentId,
      );
      throw new EnrollmentTokenInvalidError('expired');
    }

    const claim = await tenantClient.agentEnrollmentToken.updateMany({
      where: { id: tokenRow.id, usedAt: null },
      data: { usedAt: new Date() },
    });
    if (claim.count === 0) {
      // Lost a race with a concurrent enrollment attempt for this same token.
      await this.recordEnrollmentFailure(
        tenantClient,
        tenantId,
        'used',
        tokenRow.agentId,
      );
      throw new EnrollmentTokenInvalidError('used');
    }

    const issued = await this.certificateAuthority.issueCertificate(
      tenantClient,
      tokenRow.agent,
      csrPem,
    );

    await tenantClient.agent.update({
      where: { id: tokenRow.agentId },
      data: { status: 'ACTIVE' },
    });

    this.logger.log(
      `Agent "${tokenRow.agent.identifier}" enrolled successfully`,
    );

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.AGENT_ENROLLED,
      actor: { type: 'agent', id: tokenRow.agentId },
      data: {
        agentId: tokenRow.agentId,
        agentIdentifier: tokenRow.agent.identifier,
        serialNumber: issued.serialNumber,
        notBefore: issued.notBefore,
        notAfter: issued.notAfter,
      },
    });

    return issued;
  }

  async revokeAgent(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    agentId: string,
    reason: string,
    revokedByUserId: string,
  ): Promise<void> {
    const agent = await tenantClient.agent.findUnique({
      where: { id: agentId },
    });
    if (!agent) throw new AgentNotFoundError(agentId);

    await this.certificateAuthority.revoke(tenantClient, agentId, reason);

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.AGENT_REVOKED,
      actor: { type: 'human', id: revokedByUserId },
      data: { agentId, agentIdentifier: agent.identifier, reason },
    });
  }

  /** `agent.enrollment_failed` — actor is `system:unauthenticated` (Section 14: `POST /agents/enroll` has no JWT/human identity to attribute this to) unless a specific agent could still be resolved (a stale/reused token still names a real agent — see call sites above). */
  private async recordEnrollmentFailure(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    reason: 'not_found' | 'used' | 'expired',
    agentId?: string,
  ): Promise<void> {
    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.AGENT_ENROLLMENT_FAILED,
      actor: agentId
        ? { type: 'agent', id: agentId }
        : { type: 'system', id: 'system:unauthenticated' },
      data: { reason },
    });
  }
}
