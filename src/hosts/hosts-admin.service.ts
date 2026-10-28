import { Injectable } from '@nestjs/common';
import type {
  Host,
  HostStatus,
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { CertificateAuthorityService } from '../agents/certificate-authority.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES, type AuditActor } from '../audit/audit-event-types';
import {
  cursorWhereClause,
  toCursorPage,
  type CursorPage,
  type DecodedCursor,
} from '../common/pagination/cursor-pagination';
import { isValidCidr } from './install-key.util';
import { InvalidCidrError } from './install-keys.service';

export class HostNotFoundError extends Error {}
/** The requested change isn't allowed from the host's current status. */
export class HostTransitionError extends Error {}
/** Setting this parent would make an org unit its own ancestor. */
export class OrgUnitCycleError extends Error {}

export type HostDecision = 'approve' | 'reject' | 'revoke';

/** No real org tree is deeper; a longer walk means a cycle or corruption. */
const MAX_ORG_DEPTH = 64;

const ALLOWED: Record<HostDecision, { from: HostStatus[]; to: HostStatus }> = {
  approve: { from: ['PENDING', 'REJECTED'], to: 'APPROVED' },
  reject: { from: ['PENDING'], to: 'REJECTED' },
  revoke: { from: ['PENDING', 'APPROVED'], to: 'REVOKED' },
};

const EVENT: Record<HostDecision, string> = {
  approve: AUDIT_EVENT_TYPES.HOST_APPROVED,
  reject: AUDIT_EVENT_TYPES.HOST_REJECTED,
  revoke: AUDIT_EVENT_TYPES.HOST_REVOKED,
};

/** Admin operations on hosts, groups, org units and approval rules (docs/hosts.md). */
@Injectable()
export class HostsAdminService {
  constructor(
    private readonly audit: AuditService,
    private readonly ca: CertificateAuthorityService,
  ) {}

  listHosts(
    client: TenantPrismaClient,
    input: {
      status?: HostStatus;
      hostGroupId?: string;
      limit: number;
      cursor?: DecodedCursor;
    },
  ): Promise<CursorPage<Host>> {
    return client.host
      .findMany({
        where: {
          ...(input.status ? { status: input.status } : {}),
          ...(input.hostGroupId ? { hostGroupId: input.hostGroupId } : {}),
          ...cursorWhereClause('createdAt', input.cursor),
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: input.limit + 1,
      })
      .then((rows) => toCursorPage(rows, input.limit, (r) => r.createdAt));
  }

  /**
   * Approve, reject or revoke, audited in the same transaction. Revoking
   * also revokes the host's certificates (locally first, then OpenBao).
   */
  async decide(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    hostId: string,
    decision: HostDecision,
    opts: { keyFingerprint?: string } = {},
  ): Promise<Host> {
    const rule = ALLOWED[decision];
    const { host, publish, rekeyed } = await client.$transaction(async (tx) => {
      const current = await tx.host.findUnique({ where: { id: hostId } });
      if (!current) throw new HostNotFoundError(hostId);
      // A pending rekey (a known machine showed another key or group) is
      // decided first: approve binds the new key/group, reject drops it.
      if (current.pendingKeyFingerprint && decision !== 'revoke') {
        const approve = decision === 'approve';
        if (
          approve &&
          ((current.status !== 'PENDING' && current.status !== 'APPROVED') ||
            opts.keyFingerprint !== current.pendingKeyFingerprint)
        ) {
          throw new HostTransitionError(
            'approving a rekey needs the host PENDING or APPROVED and the exact pending keyFingerprint',
          );
        }
        const updated = await tx.host.update({
          where: { id: hostId },
          data: {
            pendingKeyFingerprint: null,
            pendingHostGroupId: null,
            ...(approve
              ? {
                  keyFingerprint: current.pendingKeyFingerprint,
                  hostGroupId:
                    current.pendingHostGroupId ?? current.hostGroupId,
                  status: 'APPROVED' as const,
                  approvedBy: actor.id,
                  approvedAt: new Date(),
                }
              : {}),
          },
        });
        const done = await this.audit.recordInTransaction(tx, tenantId, {
          eventType: EVENT[decision] as never,
          actor,
          data: {
            hostId,
            rekey: true,
            keyChanged:
              current.pendingKeyFingerprint !== current.keyFingerprint,
            toHostGroupId: current.pendingHostGroupId,
          },
        });
        return {
          host: updated,
          publish: done,
          rekeyed:
            approve && current.pendingKeyFingerprint !== current.keyFingerprint,
        };
      }
      if (!rule.from.includes(current.status)) {
        throw new HostTransitionError(
          `cannot ${decision} a host that is ${current.status}`,
        );
      }
      const updated = await tx.host.update({
        where: { id: hostId },
        data: {
          status: rule.to,
          // Revoking or rejecting also drops any rekey waiting for approval.
          ...(decision !== 'approve'
            ? { pendingKeyFingerprint: null, pendingHostGroupId: null }
            : {}),
          ...(decision === 'approve'
            ? { approvedBy: actor.id, approvedAt: new Date() }
            : {}),
        },
      });
      const done = await this.audit.recordInTransaction(tx, tenantId, {
        eventType: EVENT[decision] as never,
        actor,
        data: { hostId, from: current.status, to: rule.to },
      });
      return { host: updated, publish: done, rekeyed: false };
    });
    publish();
    // The old key's certificates stop once the new key is bound.
    if (decision === 'revoke' || rekeyed) {
      await this.ca.revokeHostCertificates(client, hostId);
    }
    return host;
  }

  /** Runs `change` and records `eventType` with its result in one transaction. */
  private async audited<T>(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    eventType: string,
    change: (
      tx: Prisma.TransactionClient,
    ) => Promise<{ result: T; data: unknown }>,
  ): Promise<T> {
    const { result, publish } = await client.$transaction(async (tx) => {
      const { result: r, data } = await change(tx);
      const done = await this.audit.recordInTransaction(tx, tenantId, {
        eventType: eventType as never,
        actor,
        data,
      });
      return { result: r, publish: done };
    });
    publish();
    return result;
  }

  createHostGroup(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: { name: string; orgUnitId?: string | null },
  ) {
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.HOST_GROUP_CHANGED,
      async (tx) => {
        const group = await tx.hostGroup.create({
          data: { name: input.name, orgUnitId: input.orgUnitId ?? null },
        });
        return {
          result: group,
          data: { hostGroupId: group.id, before: null, after: group },
        };
      },
    );
  }

  updateHostGroup(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
    input: { name?: string; orgUnitId?: string | null },
  ) {
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.HOST_GROUP_CHANGED,
      async (tx) => {
        const before = await tx.hostGroup.findUnique({ where: { id } });
        const group = await tx.hostGroup.update({ where: { id }, data: input });
        return {
          result: group,
          data: { hostGroupId: id, before, after: group },
        };
      },
    );
  }

  createOrgUnit(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: { name: string; parentId?: string | null },
  ) {
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.ORG_UNIT_CHANGED,
      async (tx) => {
        const unit = await tx.orgUnit.create({
          data: { name: input.name, parentId: input.parentId ?? null },
        });
        return {
          result: unit,
          data: { orgUnitId: unit.id, before: null, after: unit },
        };
      },
    );
  }

  /**
   * Refuses a parent that is the unit itself or one of its descendants. The
   * walk up is bounded (a visited set and a depth cap) and runs in the same
   * serializable transaction as the move, so two concurrent moves can't
   * build a cycle between them. Audited.
   */
  async updateOrgUnit(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
    input: { name?: string; parentId?: string | null },
  ) {
    const { unit, publish } = await client.$transaction(
      async (tx) => {
        const visited = new Set<string>();
        for (let at = input.parentId ?? null; at !== null;) {
          if (at === id || visited.has(at) || visited.size >= MAX_ORG_DEPTH) {
            throw new OrgUnitCycleError(id);
          }
          visited.add(at);
          at =
            (await tx.orgUnit.findUnique({ where: { id: at } }))?.parentId ??
            null;
        }
        const before = await tx.orgUnit.findUnique({ where: { id } });
        const updated = await tx.orgUnit.update({ where: { id }, data: input });
        const done = await this.audit.recordInTransaction(tx, tenantId, {
          eventType: AUDIT_EVENT_TYPES.ORG_UNIT_CHANGED,
          actor,
          data: { orgUnitId: id, before, after: updated },
        });
        return { unit: updated, publish: done };
      },
      { isolationLevel: 'Serializable' },
    );
    publish();
    return unit;
  }

  createApprovalRule(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: {
      hostGroupId?: string | null;
      hostnamePattern?: string | null;
      cidrs?: string[];
      requireTpm?: boolean;
      enabled?: boolean;
    },
  ) {
    assertCidrs(input.cidrs);
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.HOST_APPROVAL_RULE_CHANGED,
      async (tx) => {
        const rule = await tx.hostApprovalRule.create({
          data: {
            hostGroupId: input.hostGroupId ?? null,
            hostnamePattern: input.hostnamePattern ?? null,
            cidrs: input.cidrs ?? [],
            requireTpm: input.requireTpm ?? false,
            enabled: input.enabled ?? true,
          },
        });
        return {
          result: rule,
          data: { ruleId: rule.id, before: null, after: rule },
        };
      },
    );
  }

  updateApprovalRule(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
    input: {
      hostnamePattern?: string | null;
      cidrs?: string[];
      requireTpm?: boolean;
      enabled?: boolean;
    },
  ) {
    assertCidrs(input.cidrs);
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.HOST_APPROVAL_RULE_CHANGED,
      async (tx) => {
        const before = await tx.hostApprovalRule.findUnique({ where: { id } });
        const rule = await tx.hostApprovalRule.update({
          where: { id },
          data: input,
        });
        return { result: rule, data: { ruleId: id, before, after: rule } };
      },
    );
  }
}

function assertCidrs(cidrs: string[] | undefined): void {
  const bad = (cidrs ?? []).filter((c) => !isValidCidr(c));
  if (bad.length > 0) throw new InvalidCidrError(bad.join(', '));
}
