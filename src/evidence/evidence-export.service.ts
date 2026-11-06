import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import type { AppConfig } from '../config/env.validation';
import {
  AuditCheckpointIndexError,
  AuditEventNotCheckpointedError,
  type AuditEventProof,
  AuditProofService,
  type SealedCheckpoint,
} from '../audit/checkpoint/audit-proof.service';

/** An event's inclusion proof in a bundle; its SEAL is in `bundle.checkpoints`. */
export type EvidenceEventProof = Omit<AuditEventProof, 'checkpoint'> & {
  checkpointSeq: string;
};

/** Proofs are built this many at a time, not all at once. */
const PROOF_CONCURRENCY = 16;
import {
  CHECKPOINT_PUBLIC_KEYS,
  type CheckpointKeyLookup,
  type CheckpointPublicKey,
  checkpointHashOf,
  NoCheckpointKeyError,
  verifyCheckpointSignature,
} from '../audit/checkpoint/checkpoint-format';
import { computeEventHash } from '../audit/audit-hash';
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
    partitionSeq: number;
    /** `null` while no SEAL covers the event yet (they are written every second). */
    proof: EvidenceEventProof | null;
  }[];
  /** The tenant's SEAL signing key, for offline checks of every `proof`. */
  checkpointPublicKey: CheckpointPublicKey | null;
  /** Every SEAL a proof in `events` refers to (by `proof.checkpointSeq`), once each. */
  checkpoints: SealedCheckpoint[];
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

/** Rows per statement when reading the audit events of an export. */
export const EVIDENCE_PAGE_SIZE = 2000;

/**
 * Reads the matching audit events in sequence order, one bounded page per statement, so a large
 * export never runs into the database statement timeout.
 */
export async function readAuditEventsPaged(
  tenantClient: TenantPrismaClient,
  where: Prisma.AuditEventWhereInput,
  pageSize = EVIDENCE_PAGE_SIZE,
) {
  type Row = Awaited<
    ReturnType<typeof tenantClient.auditEvent.findMany>
  >[number];
  const all: Row[] = [];
  for (let after: number | null = null; ;) {
    const page: Row[] = await tenantClient.auditEvent.findMany({
      where:
        after === null ? where : { AND: [where, { sequence: { gt: after } }] },
      orderBy: { sequence: 'asc' },
      take: pageSize,
    });
    all.push(...page);
    if (page.length < pageSize) return all;
    after = page[page.length - 1]!.sequence;
  }
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

    const candidateEvents = await readAuditEventsPaged(tenantClient, where);

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
    const checkpoints = new Map<string, SealedCheckpoint>();
    const proofs: (EvidenceEventProof | null)[] = [];
    for (let start = 0; start < events.length; start += PROOF_CONCURRENCY) {
      const chunk = await Promise.all(
        events.slice(start, start + PROOF_CONCURRENCY).map((event) =>
          this.proofs
            .proveEvent(tenantClient, event.id)
            .catch((error: unknown) => {
              if (error instanceof AuditEventNotCheckpointedError) return null;
              throw error;
            }),
        ),
      );
      for (const proof of chunk) {
        if (!proof) {
          proofs.push(null);
          continue;
        }
        const { checkpoint, ...rest } = proof;
        checkpoints.set(checkpoint.seq, checkpoint);
        proofs.push({ ...rest, checkpointSeq: checkpoint.seq });
      }
    }

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
      events: events.map((event, i) => ({
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
        partitionSeq: event.partitionSeq,
        proof: proofs[i]!,
      })),
      checkpoints: [...checkpoints.values()],
      checkpointPublicKey: await this.checkpointKeys
        .publicKey(tenantId)
        .catch((error: unknown) => {
          if (error instanceof NoCheckpointKeyError) return null; // nothing sealed yet
          throw error;
        }),
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
  /**
   * `tenantClient`, when it is the bundle's own tenant, lets verify tell a
   * proof that was never available (event not yet sealed at export) from one
   * that was stripped from the bundle (a checkpoint covers the event now).
   */
  async verify(
    bundle: unknown,
    signature: string,
    tenantClient?: TenantPrismaClient,
  ): Promise<EvidenceVerifyResult> {
    const signed = await verifyEvidenceBundle(
      bundle,
      signature,
      this.configService.get('APPROVAL_GRANT_SIGNING_SECRET', { infer: true }),
    );
    if (!signed.valid) return signed;
    return this.verifyProofs(
      bundle as Partial<EvidenceBundleContent>,
      tenantClient,
    );
  }

  /**
   * Checks every event's inclusion proof against a SEAL signed by the
   * tenant's real key (looked up here, not trusted from the bundle), so a
   * bundle stays checkable even if the HMAC export secret leaked.
   */
  private async verifyProofs(
    bundle: Partial<EvidenceBundleContent>,
    tenantClient: TenantPrismaClient | undefined,
  ): Promise<EvidenceVerifyResult> {
    const events = Array.isArray(bundle.events) ? bundle.events : [];
    const withProof = events.filter((e) => e.proof);
    for (const event of events.filter((e) => !e.proof)) {
      const missing = await this.judgeMissingProof(event, tenantClient);
      if (missing !== 'not_sealed_yet') {
        return { valid: false, reason: missing };
      }
    }
    if (withProof.length === 0) {
      return { valid: true, proofsVerified: 0, proofsMissing: events.length };
    }
    if (typeof bundle.tenantId !== 'string') {
      return { valid: false, reason: 'proof_invalid' };
    }
    const key = await this.checkpointKeys
      .publicKey(bundle.tenantId)
      .catch((error: unknown) => {
        if (error instanceof NoCheckpointKeyError) return null;
        throw error;
      });
    if (!key || bundle.checkpointPublicKey?.publicKeyPem !== key.publicKeyPem) {
      return { valid: false, reason: 'proof_invalid' };
    }
    const sealed = new Map(
      (Array.isArray(bundle.checkpoints) ? bundle.checkpoints : []).map((c) => [
        c.seq,
        c,
      ]),
    );
    for (const event of withProof) {
      if (!proofHolds(event, key, sealed)) {
        return { valid: false, reason: 'proof_invalid' };
      }
    }
    return {
      valid: true,
      proofsVerified: withProof.length,
      proofsMissing: events.length - withProof.length,
    };
  }

  /**
   * A missing proof is acceptable only when the event is in the tenant's log
   * with the same hash and no checkpoint covers it yet (it was exported in
   * the second before its SEAL). Anything that can't be established is
   * unverifiable, never valid.
   */
  private async judgeMissingProof(
    event: EvidenceBundleContent['events'][number],
    tenantClient: TenantPrismaClient | undefined,
  ): Promise<
    'not_sealed_yet' | 'proof_missing' | 'proof_invalid' | 'proof_unverifiable'
  > {
    if (!tenantClient) return 'proof_unverifiable';
    const stored = await tenantClient.auditEvent.findUnique({
      where: { id: event.id },
      select: { eventHash: true },
    });
    if (!stored) return 'proof_unverifiable'; // pruned, or never existed
    if (stored.eventHash !== event.eventHash || !eventHashHolds(event)) {
      return 'proof_invalid';
    }
    try {
      await this.proofs.proveEvent(tenantClient, event.id);
      return 'proof_missing'; // a checkpoint covers it: the proof was removed
    } catch (error) {
      if (error instanceof AuditEventNotCheckpointedError) {
        return 'not_sealed_yet';
      }
      if (error instanceof AuditCheckpointIndexError) return 'proof_invalid';
      throw error;
    }
  }
}

export type EvidenceVerifyResult =
  | { valid: true; proofsVerified: number; proofsMissing: number }
  | { valid: false; reason: string };

function eventHashHolds(
  event: EvidenceBundleContent['events'][number],
): boolean {
  try {
    return (
      computeEventHash({
        id: event.id,
        eventType: event.eventType,
        correlationId: event.correlationId,
        actor: event.actor,
        timestamp: event.timestamp,
        data: event.data,
        previousHash: event.previousHash,
      }) === event.eventHash
    );
  } catch {
    return false;
  }
}

function proofHolds(
  event: EvidenceBundleContent['events'][number],
  key: CheckpointPublicKey,
  sealed: Map<string, SealedCheckpoint>,
): boolean {
  const p = event.proof!;
  const cp = sealed.get(p.checkpointSeq);
  if (!cp) return false;
  try {
    // The leaf must be this event's hash recomputed from its own fields,
    // not just the eventHash the bundle claims.
    if (!eventHashHolds(event)) return false;
    const range = cp.roots.find(
      (r) =>
        r.partition === event.partition &&
        Number(r.fromSeq) <= event.partitionSeq &&
        Number(r.toSeq) >= event.partitionSeq,
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
