import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import type { AppConfig } from '../config/env.validation';
import {
  AuditEventNotCheckpointedError,
  type AuditEventProof,
  AuditProofService,
} from '../audit/checkpoint/audit-proof.service';
import {
  CHECKPOINT_PUBLIC_KEYS,
  type CheckpointKeyLookup,
  type CheckpointPublicKey,
  checkpointHashOf,
  verifyCheckpointSignature,
} from '../audit/checkpoint/checkpoint-format';
import { verifyInclusion } from '../audit/merkle';
import type { EvidenceExportRequest } from './evidence-export.validation';
import {
  EvidenceBundleSignature,
  signEvidenceBundle,
  verifyEvidenceBundle,
} from './evidence-signing.util';

export interface EvidenceExportResult {
  exportId: string;
  bundle: EvidenceBundleContent;
  signature: EvidenceBundleSignature;
}

export interface EvidenceBundleContent {
  tenantId: string;
  exportId: string;
  exportedBy: string;
  generatedAt: string;
  filter: {
    since: string | null;
    until: string | null;
    agentId: string | null;
    taskId: string | null;
    correlationId: string | null;
  };
  /**
   * The matched `AuditEvent`s, in recorded order, each with its hash
   * fields, its audit partition and position, and — once a SEAL covers it —
   * an inclusion proof (Section 49: "let a recipient verify those specific
   * events weren't tampered with independent of trusting this export").
   * A recipient recomputes each `eventHash` (`computeEventHash`,
   * `src/audit/audit-hash.ts`), hashes it up `proof.proof` to `proof.root`,
   * finds that root in `proof.checkpoint.roots`, and verifies the
   * checkpoint's Ed25519 signature with `checkpointPublicKey`. Events
   * directly after one another in a partition also link by `previousHash`.
   * `GET /audit/verify` remains the full-log check.
   */
  events: {
    id: string;
    sequence: number;
    eventType: string;
    correlationId: string;
    actor: unknown;
    timestamp: string;
    data: unknown;
    previousHash: string | null;
    eventHash: string;
    partition: number;
    /** Decimal string (a bigint). */
    partitionSeq: string;
    /** `null` while no SEAL covers the event yet (they are written every second). */
    proof: AuditEventProof | null;
  }[];
  /** The tenant's SEAL signing key, for offline checks of every `proof`. */
  checkpointPublicKey: CheckpointPublicKey;
  /**
   * Directly-relevant context pulled from the *real* tables the retrofitted
   * decision points already write to (Section 49: "don't duplicate data
   * into a new export-specific model") — never a copy that could drift
   * from the operational rows themselves.
   */
  context: {
    agents: {
      id: string;
      slug: string;
      identifier: string;
      displayName: string;
      status: string;
      certificates: {
        serialNumber: string;
        subject: string;
        notBefore: string;
        notAfter: string;
        revokedAt: string | null;
        revocationReason: string | null;
      }[];
    }[];
    tasks: {
      id: string;
      name: string;
      requesterId: string;
      assignedAgentId: string;
      parentTaskId: string | null;
      status: string;
      riskCeiling: number;
      expiresAt: string;
      createdAt: string;
    }[];
    taskDelegations: {
      id: string;
      parentTaskId: string;
      childTaskId: string;
      createdAt: string;
    }[];
    policyVersions: {
      id: string;
      policyId: string;
      policyName: string;
      version: number;
      status: string;
      contentHash: string;
      publishedAt: string | null;
    }[];
    approvalRequests: {
      id: string;
      taskId: string;
      agentId: string;
      toolId: string;
      actionId: string;
      resource: string;
      riskScore: number;
      status: string;
      requestedAt: string;
      expiresAt: string;
    }[];
    approvalDecisions: {
      id: string;
      approvalRequestId: string;
      approverId: string;
      decision: string;
      reason: string | null;
      decidedAt: string;
    }[];
    authorizationGrants: {
      id: string;
      approvalRequestId: string;
      taskId: string;
      agentId: string;
      toolId: string;
      actionId: string;
      riskScore: number;
      issuedAt: string;
      expiresAt: string;
      consumedAt: string | null;
    }[];
    toolInvocations: {
      id: string;
      taskId: string;
      agentId: string;
      toolId: string;
      actionId: string;
      resource: string;
      status: string;
      startedAt: string;
      completedAt: string | null;
      errorMessage: string | null;
    }[];
  };
}

/**
 * Phase 9b (Evidence export, Section 49). Gathers the `AuditEvent`s
 * matching a filter plus directly-relevant operational context, and
 * returns a signed/hashed bundle (`EvidenceExportService.export`).
 *
 * **Filtering**: `since`/`until`/`correlationId` are real, directly
 * queryable `AuditEvent` columns. `agentId`/`taskId` are NOT columns on
 * `AuditEvent` (Section 46's event shape carries them inside the
 * heterogeneous `data`/`actor` JSON, which differs per `eventType` — see
 * `docs/audit-chain.md`'s retrofit-point table) — this service applies a
 * bounded post-filter over the time/correlation-scoped result set,
 * matching an event whose `actor.id` (when `actor.type === 'agent'`) or
 * whose `data` carries a well-known id field
 * (`agentId`/`assignedAgentId`/`childAgentId`/`taskId`/`parentTaskId`/
 * `childTaskId`) equals the requested id. This is a real, tested match —
 * not a full-text scan of arbitrary nested content — documented here so a
 * caller understands its scope: an `agentId`/`taskId` filter finds every
 * event *about* that agent/task via its known reference fields, not every
 * event that merely mentions the id somewhere unexpected in `data`.
 */
@Injectable()
export class EvidenceExportService {
  constructor(
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly proofs: AuditProofService,
    @Inject(CHECKPOINT_PUBLIC_KEYS)
    private readonly checkpointKeys: CheckpointKeyLookup,
  ) {}

  async export(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    exportedBy: string,
    filter: EvidenceExportRequest,
  ): Promise<EvidenceExportResult> {
    const where: Prisma.AuditEventWhereInput = {};
    if (filter.since || filter.until) {
      where.timestamp = {
        ...(filter.since ? { gte: filter.since } : {}),
        ...(filter.until ? { lte: filter.until } : {}),
      };
    }
    if (filter.correlationId) where.correlationId = filter.correlationId;

    const candidateEvents = await tenantClient.auditEvent.findMany({
      where,
      orderBy: { sequence: 'asc' },
    });

    const events = candidateEvents.filter((event) =>
      matchesAgentOrTask(event, filter.agentId, filter.taskId),
    );

    const agentIds = new Set<string>();
    const taskIds = new Set<string>();
    const policyVersionIds = new Set<string>();
    const approvalRequestIds = new Set<string>();

    for (const event of events) {
      collectReferencedIds(
        event,
        agentIds,
        taskIds,
        policyVersionIds,
        approvalRequestIds,
      );
    }

    const [
      agents,
      tasks,
      taskDelegations,
      policyVersions,
      approvalRequests,
      approvalDecisions,
      authorizationGrants,
      toolInvocations,
    ] = await Promise.all([
      agentIds.size
        ? tenantClient.agent.findMany({
            where: { id: { in: [...agentIds] } },
            include: { certificates: true },
          })
        : Promise.resolve([]),
      taskIds.size
        ? tenantClient.task.findMany({ where: { id: { in: [...taskIds] } } })
        : Promise.resolve([]),
      taskIds.size
        ? tenantClient.taskDelegation.findMany({
            where: {
              OR: [
                { parentTaskId: { in: [...taskIds] } },
                { childTaskId: { in: [...taskIds] } },
              ],
            },
          })
        : Promise.resolve([]),
      policyVersionIds.size
        ? tenantClient.policyVersion.findMany({
            where: { id: { in: [...policyVersionIds] } },
            include: { policy: true },
          })
        : Promise.resolve([]),
      approvalRequestIds.size
        ? tenantClient.approvalRequest.findMany({
            where: { id: { in: [...approvalRequestIds] } },
          })
        : Promise.resolve([]),
      approvalRequestIds.size
        ? tenantClient.approvalDecision.findMany({
            where: { approvalRequestId: { in: [...approvalRequestIds] } },
          })
        : Promise.resolve([]),
      approvalRequestIds.size
        ? tenantClient.authorizationGrant.findMany({
            where: { approvalRequestId: { in: [...approvalRequestIds] } },
          })
        : Promise.resolve([]),
      taskIds.size
        ? tenantClient.toolInvocation.findMany({
            where: { taskId: { in: [...taskIds] } },
          })
        : Promise.resolve([]),
    ]);

    const exportId = randomUUID();
    const bundle: EvidenceBundleContent = {
      tenantId,
      exportId,
      exportedBy,
      generatedAt: new Date().toISOString(),
      filter: {
        since: filter.since?.toISOString() ?? null,
        until: filter.until?.toISOString() ?? null,
        agentId: filter.agentId ?? null,
        taskId: filter.taskId ?? null,
        correlationId: filter.correlationId ?? null,
      },
      events: await Promise.all(
        events.map(async (event) => ({
          id: event.id,
          sequence: event.sequence,
          eventType: event.eventType,
          correlationId: event.correlationId,
          actor: event.actor,
          timestamp: event.timestamp.toISOString(),
          data: event.data,
          previousHash: event.previousHash,
          eventHash: event.eventHash,
          partition: event.partition,
          partitionSeq: event.partitionSeq.toString(),
          proof: await this.proofs
            .proveEvent(tenantClient, event.id)
            .catch((error: unknown) => {
              if (error instanceof AuditEventNotCheckpointedError) return null;
              throw error;
            }),
        })),
      ),
      checkpointPublicKey: await this.checkpointKeys.publicKey(tenantId),
      context: {
        agents: agents.map((agent) => ({
          id: agent.id,
          slug: agent.slug,
          identifier: agent.identifier,
          displayName: agent.displayName,
          status: agent.status,
          certificates: agent.certificates.map((cert) => ({
            serialNumber: cert.serialNumber,
            subject: cert.subject,
            notBefore: cert.notBefore.toISOString(),
            notAfter: cert.notAfter.toISOString(),
            revokedAt: cert.revokedAt?.toISOString() ?? null,
            revocationReason: cert.revocationReason ?? null,
          })),
        })),
        tasks: tasks.map((task) => ({
          id: task.id,
          name: task.name,
          requesterId: task.requesterId,
          assignedAgentId: task.assignedAgentId,
          parentTaskId: task.parentTaskId,
          status: task.status,
          riskCeiling: task.riskCeiling,
          expiresAt: task.expiresAt.toISOString(),
          createdAt: task.createdAt.toISOString(),
        })),
        taskDelegations: taskDelegations.map((delegation) => ({
          id: delegation.id,
          parentTaskId: delegation.parentTaskId,
          childTaskId: delegation.childTaskId,
          createdAt: delegation.createdAt.toISOString(),
        })),
        policyVersions: policyVersions.map((version) => ({
          id: version.id,
          policyId: version.policyId,
          policyName: version.policy.name,
          version: version.version,
          status: version.status,
          contentHash: version.contentHash,
          publishedAt: version.publishedAt?.toISOString() ?? null,
        })),
        approvalRequests: approvalRequests.map((request) => ({
          id: request.id,
          taskId: request.taskId,
          agentId: request.agentId,
          toolId: request.toolId,
          actionId: request.actionId,
          resource: request.resource,
          riskScore: request.riskScore,
          status: request.status,
          requestedAt: request.requestedAt.toISOString(),
          expiresAt: request.expiresAt.toISOString(),
        })),
        approvalDecisions: approvalDecisions.map((decision) => ({
          id: decision.id,
          approvalRequestId: decision.approvalRequestId,
          approverId: decision.approverId,
          decision: decision.decision,
          reason: decision.reason,
          decidedAt: decision.decidedAt.toISOString(),
        })),
        authorizationGrants: authorizationGrants.map((grant) => ({
          id: grant.id,
          approvalRequestId: grant.approvalRequestId,
          taskId: grant.taskId,
          agentId: grant.agentId,
          toolId: grant.toolId,
          actionId: grant.actionId,
          riskScore: grant.riskScore,
          issuedAt: grant.issuedAt.toISOString(),
          expiresAt: grant.expiresAt.toISOString(),
          consumedAt: grant.consumedAt?.toISOString() ?? null,
        })),
        toolInvocations: toolInvocations.map((invocation) => ({
          id: invocation.id,
          taskId: invocation.taskId,
          agentId: invocation.agentId,
          toolId: invocation.toolId,
          actionId: invocation.actionId,
          resource: invocation.resource,
          status: invocation.status,
          startedAt: invocation.startedAt.toISOString(),
          completedAt: invocation.completedAt?.toISOString() ?? null,
          errorMessage: invocation.errorMessage,
        })),
      },
    };

    const secret = this.configService.get('APPROVAL_GRANT_SIGNING_SECRET', {
      infer: true,
    });
    const signature = await signEvidenceBundle(bundle, exportId, secret);

    return { exportId, bundle, signature };
  }

  /**
   * Verifies a bundle server-side, so a holder of the bundle never needs
   * the signing secret (Gate 0 finding R9: the demo agent used to read it
   * from the API's `.env`). Offline verification with a public key is
   * finding F10's fix.
   */
  async verify(
    bundle: unknown,
    signature: string,
  ): Promise<EvidenceVerifyResult> {
    const signed = await verifyEvidenceBundle(
      bundle,
      signature,
      this.configService.get('APPROVAL_GRANT_SIGNING_SECRET', { infer: true }),
    );
    if (!signed.valid) return signed;
    return this.verifyProofs(bundle as Partial<EvidenceBundleContent>);
  }

  /**
   * Checks every event's inclusion proof against a SEAL signed by the
   * tenant's real key (looked up here, not trusted from the bundle), so a
   * bundle stays checkable even if the HMAC export secret leaked.
   */
  private async verifyProofs(
    bundle: Partial<EvidenceBundleContent>,
  ): Promise<EvidenceVerifyResult> {
    const events = Array.isArray(bundle.events) ? bundle.events : [];
    const withProof = events.filter((e) => e.proof);
    if (withProof.length === 0) {
      return { valid: true, proofsVerified: 0, proofsMissing: events.length };
    }
    if (typeof bundle.tenantId !== 'string') {
      return { valid: false, reason: 'proof_invalid' };
    }
    const key = await this.checkpointKeys.publicKey(bundle.tenantId);
    if (bundle.checkpointPublicKey?.publicKeyPem !== key.publicKeyPem) {
      return { valid: false, reason: 'proof_invalid' };
    }
    for (const event of withProof) {
      if (!proofHolds(event, key)) {
        return { valid: false, reason: 'proof_invalid' };
      }
    }
    return {
      valid: true,
      proofsVerified: withProof.length,
      proofsMissing: events.length - withProof.length,
    };
  }
}

export type EvidenceVerifyResult =
  | { valid: true; proofsVerified: number; proofsMissing: number }
  | { valid: false; reason: string };

function proofHolds(
  event: EvidenceBundleContent['events'][number],
  key: CheckpointPublicKey,
): boolean {
  const p = event.proof!;
  const cp = p.checkpoint;
  try {
    const range = cp.roots.find(
      (r) =>
        r.partition === event.partition &&
        BigInt(r.fromSeq) <= BigInt(event.partitionSeq) &&
        BigInt(r.toSeq) >= BigInt(event.partitionSeq),
    );
    return (
      p.eventId === event.id &&
      p.leaf === event.eventHash &&
      range !== undefined &&
      range.root === p.root &&
      verifyInclusion(p.leaf, p.proof, p.root) &&
      checkpointHashOf({
        seq: BigInt(cp.seq),
        createdAt: new Date(cp.createdAt),
        partitionHeads: cp.partitionHeads,
        roots: cp.roots,
        previousCheckpointHash: cp.previousCheckpointHash,
      }) === cp.checkpointHash &&
      cp.keyId === key.keyId &&
      verifyCheckpointSignature(
        cp.checkpointHash,
        cp.signature,
        key.publicKeyPem,
      )
    );
  } catch {
    return false; // malformed proof fields
  }
}

interface AuditEventLike {
  actor: unknown;
  data: unknown;
}

function matchesAgentOrTask(
  event: AuditEventLike,
  agentId: string | undefined,
  taskId: string | undefined,
): boolean {
  if (!agentId && !taskId) return true;

  const actor = isRecord(event.actor) ? event.actor : {};
  const data = isRecord(event.data) ? event.data : {};

  if (agentId) {
    const agentMatch =
      (actor.type === 'agent' && actor.id === agentId) ||
      data.agentId === agentId ||
      data.assignedAgentId === agentId ||
      data.childAgentId === agentId;
    if (agentMatch) return true;
  }

  if (taskId) {
    const taskMatch =
      data.taskId === taskId ||
      data.parentTaskId === taskId ||
      data.childTaskId === taskId;
    if (taskMatch) return true;
  }

  return false;
}

function collectReferencedIds(
  event: AuditEventLike,
  agentIds: Set<string>,
  taskIds: Set<string>,
  policyVersionIds: Set<string>,
  approvalRequestIds: Set<string>,
): void {
  const actor = isRecord(event.actor) ? event.actor : {};
  const data = isRecord(event.data) ? event.data : {};

  if (actor.type === 'agent' && typeof actor.id === 'string') {
    agentIds.add(actor.id);
  }
  for (const key of ['agentId', 'assignedAgentId', 'childAgentId']) {
    if (typeof data[key] === 'string') agentIds.add(data[key]);
  }
  for (const key of ['taskId', 'parentTaskId', 'childTaskId']) {
    if (typeof data[key] === 'string') taskIds.add(data[key]);
  }
  if (typeof data.policyVersionId === 'string') {
    policyVersionIds.add(data.policyVersionId);
  }
  if (typeof data.approvalRequestId === 'string') {
    approvalRequestIds.add(data.approvalRequestId);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
