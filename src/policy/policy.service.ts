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
import { computeContentHash } from './policy-content-codec';
import { PolicyContent } from './policy-content.schema';
import {
  PolicyNotFoundError,
  PolicyVersionNotDraftError,
  PolicyVersionNotFoundError,
} from './policy.errors';

export interface ListPoliciesInput {
  limit: number;
  cursor?: DecodedCursor;
}

export interface PolicyListRow {
  id: string;
  name: string;
  description: string | null;
  createdAt: Date;
  currentVersion: {
    id: string;
    policyId: string;
    version: number;
    status: string;
    content: unknown;
    contentHash: string;
    authorId: string;
    reason: string | null;
    previousVersionId: string | null;
    publishedAt: Date | null;
    createdAt: Date;
  } | null;
}

export interface CreatePolicyInput {
  name: string;
  description?: string | null;
  content: PolicyContent;
  authorId: string;
  reason?: string | null;
}

export interface CreatePolicyVersionInput {
  content: PolicyContent;
  authorId: string;
  reason?: string | null;
}

/**
 * `Policy`/`PolicyVersion` CRUD (Sections 21-22 — see docs/policy-model.md).
 * Never exposes an update/delete for a published version — see
 * `src/policy/policy.controller.ts`'s doc comment for why that's permanent,
 * not "not built yet."
 */
@Injectable()
export class PolicyService {
  private readonly logger = new Logger(PolicyService.name);

  constructor(private readonly auditService: AuditService) {}

  /** Creates a `Policy` + its first (`version` 1) `DRAFT` `PolicyVersion`. */
  async createPolicy(
    tenantClient: TenantPrismaClient,
    input: CreatePolicyInput,
  ) {
    const policy = await tenantClient.policy.create({
      data: { name: input.name, description: input.description ?? null },
    });

    const version = await tenantClient.policyVersion.create({
      data: {
        policyId: policy.id,
        version: 1,
        status: 'DRAFT',
        content: input.content,
        contentHash: computeContentHash(input.content),
        authorId: input.authorId,
        reason: input.reason ?? null,
        previousVersionId: null,
      },
    });

    this.logger.log(`Policy "${policy.id}" ("${policy.name}") created`);
    return { policy, version };
  }

  /**
   * Creates a new `DRAFT` version (`version` n+1) chained off whichever
   * version (`DRAFT` or `PUBLISHED`) was this policy's latest at the time
   * of creation — see `PolicyVersion.previousVersionId`'s schema doc
   * comment for why this is the chain predecessor, not necessarily the
   * version whose content is being reused for a rollback.
   */
  async createVersion(
    tenantClient: TenantPrismaClient,
    policyId: string,
    input: CreatePolicyVersionInput,
  ) {
    await this.getPolicyOrThrow(tenantClient, policyId);

    const latest = await tenantClient.policyVersion.findFirst({
      where: { policyId },
      orderBy: { version: 'desc' },
    });
    const nextVersion = (latest?.version ?? 0) + 1;

    const version = await tenantClient.policyVersion.create({
      data: {
        policyId,
        version: nextVersion,
        status: 'DRAFT',
        content: input.content,
        contentHash: computeContentHash(input.content),
        authorId: input.authorId,
        reason: input.reason ?? null,
        previousVersionId: latest?.id ?? null,
      },
    });

    return version;
  }

  /** `DRAFT` -> `PUBLISHED`. The only transition this service ever performs on an existing version's `status` — there is no other update path (see module doc comment). */
  async publishVersion(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    policyId: string,
    versionId: string,
    publishedByUserId: string,
  ) {
    const version = await this.getVersionOrThrow(
      tenantClient,
      policyId,
      versionId,
    );
    if (version.status !== 'DRAFT') {
      throw new PolicyVersionNotDraftError(versionId, version.status);
    }

    const published = await tenantClient.policyVersion.update({
      where: { id: versionId },
      data: { status: 'PUBLISHED', publishedAt: new Date() },
    });

    this.logger.log(
      `Policy "${policyId}" version "${versionId}" (v${published.version}) published`,
    );

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.POLICY_PUBLISHED,
      actor: { type: 'human', id: publishedByUserId },
      data: {
        policyId,
        versionId: published.id,
        version: published.version,
        contentHash: published.contentHash,
        publishedAt: published.publishedAt,
      },
    });

    return published;
  }

  /**
   * `GET /policies` (Phase 11b Part 1) — cursor-paginated, newest first,
   * each row carrying its own "current published version" the same shape
   * `GET /policies/:id` already returns (Section 65's policy list needs
   * the current version's status/hash at a glance, not just the bare
   * `Policy` row). No filters: unlike task/approval/agent status, a
   * policy's own fields don't carry anything Section 65/66 asks to filter
   * list-page-side.
   *
   * Fetches the page of `Policy` rows first, then a single batched
   * `PolicyVersion` query for all of them (`status: PUBLISHED`, highest
   * `version` per `policyId` picked in application code) — one extra
   * round trip per page, not one per policy (N+1).
   */
  async listPolicies(
    tenantClient: TenantPrismaClient,
    input: ListPoliciesInput,
  ): Promise<CursorPage<PolicyListRow>> {
    const where = { ...cursorWhereClause('createdAt', input.cursor) };
    const policies = await tenantClient.policy.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
    });

    const policyIds = policies.map((p) => p.id);
    const publishedVersions =
      policyIds.length === 0
        ? []
        : await tenantClient.policyVersion.findMany({
            where: { policyId: { in: policyIds }, status: 'PUBLISHED' },
            orderBy: { version: 'desc' },
          });
    const currentByPolicyId = new Map<
      string,
      (typeof publishedVersions)[number]
    >();
    for (const version of publishedVersions) {
      if (!currentByPolicyId.has(version.policyId)) {
        currentByPolicyId.set(version.policyId, version);
      }
    }

    const rows: PolicyListRow[] = policies.map((policy) => ({
      id: policy.id,
      name: policy.name,
      description: policy.description,
      createdAt: policy.createdAt,
      currentVersion: currentByPolicyId.get(policy.id) ?? null,
    }));

    return toCursorPage(rows, input.limit, (row) => row.createdAt);
  }

  async getPolicyOrThrow(tenantClient: TenantPrismaClient, policyId: string) {
    const policy = await tenantClient.policy.findUnique({
      where: { id: policyId },
    });
    if (!policy) throw new PolicyNotFoundError(policyId);
    return policy;
  }

  /** The policy plus its "current" content — the latest `PUBLISHED` version, or `null` if none has ever been published. */
  async getCurrentPublished(
    tenantClient: TenantPrismaClient,
    policyId: string,
  ) {
    const policy = await this.getPolicyOrThrow(tenantClient, policyId);
    const current = await tenantClient.policyVersion.findFirst({
      where: { policyId, status: 'PUBLISHED' },
      orderBy: { version: 'desc' },
    });
    return { policy, current };
  }

  /** Full immutable version history, oldest first — every `DRAFT` and `PUBLISHED` row ever created for this policy. */
  async listVersions(tenantClient: TenantPrismaClient, policyId: string) {
    await this.getPolicyOrThrow(tenantClient, policyId);
    return tenantClient.policyVersion.findMany({
      where: { policyId },
      orderBy: { version: 'asc' },
    });
  }

  async getVersionOrThrow(
    tenantClient: TenantPrismaClient,
    policyId: string,
    versionId: string,
  ) {
    const version = await tenantClient.policyVersion.findUnique({
      where: { id: versionId },
    });
    if (!version || version.policyId !== policyId) {
      throw new PolicyVersionNotFoundError(policyId, versionId);
    }
    return version;
  }
}
