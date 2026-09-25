import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import { buildAgentIdentifier } from './agent-identifier';
import {
  AgentNotFoundError,
  AgentTerminatedError,
  EnrollmentFailureReason,
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

/** Terminal agent states: never issued a token, never re-enrolled (Gate 0 R4). `PENDING_ENROLLMENT` and `ACTIVE` stay enrollable. */
const TERMINAL_AGENT_STATUSES: ('REVOKED' | 'KILLED')[] = ['REVOKED', 'KILLED'];

function isTerminal(status: string): boolean {
  return (TERMINAL_AGENT_STATUSES as string[]).includes(status);
}

export interface CreateAgentInput {
  slug: string;
  displayName: string;
  tenantSlug: string;
  createdBy: string;
}

export interface ListAgentsInput {
  /** Section 65's agent list filter — real `AgentStatus` values only. */
  status?: 'PENDING_ENROLLMENT' | 'ACTIVE' | 'REVOKED' | 'KILLED';
  limit: number;
  cursor?: DecodedCursor;
}

export interface AgentSummary {
  id: string;
  slug: string;
  identifier: string;
  displayName: string;
  status: string;
  createdAt: Date;
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

  /**
   * `GET /agents` (Phase 11b Part 1) — cursor-paginated, newest first, the
   * one filter Section 65's agent list page actually needs (`status`; see
   * `docs/superpowers/specs/2026-08-19-phase11b-list-endpoints-core-pages-design.md`).
   * Tenant-scoped by construction: `tenantClient` is already this
   * request's tenant-isolated Prisma client (Phase 2 — see
   * docs/tenant-isolation.md), so there is no separate `tenantId` filter
   * to apply here.
   */
  async listAgents(
    tenantClient: TenantPrismaClient,
    input: ListAgentsInput,
  ): Promise<CursorPage<AgentSummary>> {
    const where = {
      ...(input.status ? { status: input.status } : {}),
      ...cursorWhereClause('createdAt', input.cursor),
    };
    const rows = await tenantClient.agent.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
    });
    return toCursorPage(rows, input.limit, (row) => row.createdAt);
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
    if (isTerminal(agent.status)) {
      throw new AgentTerminatedError(agentId, agent.status);
    }

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
    // A token issued before the agent was revoked or killed must not bring
    // it back: checked before OpenBao signs anything.
    if (isTerminal(tokenRow.agent.status)) {
      await this.recordEnrollmentFailure(
        tenantClient,
        tenantId,
        'agent_terminated',
        tokenRow.agentId,
      );
      throw new EnrollmentTokenInvalidError('agent_terminated');
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

    // Conditional, so a revocation that lands while the certificate is
    // being signed still wins: the agent stays REVOKED and
    // AgentMtlsGuard refuses the fresh certificate.
    await tenantClient.agent.updateMany({
      where: {
        id: tokenRow.agentId,
        status: { notIn: TERMINAL_AGENT_STATUSES },
      },
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

    const { caRevocationPending } = await this.certificateAuthority.revoke(
      tenantClient,
      agentId,
      reason,
    );

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.AGENT_REVOKED,
      actor: { type: 'human', id: revokedByUserId },
      data: {
        agentId,
        agentIdentifier: agent.identifier,
        reason,
        caRevocationPending,
      },
    });
  }

  /** `agent.enrollment_failed` — actor is `system:unauthenticated` (Section 14: `POST /agents/enroll` has no JWT/human identity to attribute this to) unless a specific agent could still be resolved (a stale/reused token still names a real agent — see call sites above). */
  private async recordEnrollmentFailure(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    reason: EnrollmentFailureReason,
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
