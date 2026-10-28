import { Injectable } from '@nestjs/common';
import type {
  Host,
  HostStatus,
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
  ): Promise<Host> {
    const rule = ALLOWED[decision];
    const { host, publish, rekeyed } = await client.$transaction(async (tx) => {
      const current = await tx.host.findUnique({ where: { id: hostId } });
      if (!current) throw new HostNotFoundError(hostId);
      // A pending rekey (a known machine showed another key or group) is
      // decided first: approve binds the new key/group, reject drops it.
      if (current.pendingKeyFingerprint && decision !== 'revoke') {
        const approve = decision === 'approve';
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

  createHostGroup(
    client: TenantPrismaClient,
    input: { name: string; orgUnitId?: string | null },
  ) {
    return client.hostGroup.create({
      data: { name: input.name, orgUnitId: input.orgUnitId ?? null },
    });
  }

  updateHostGroup(
    client: TenantPrismaClient,
    id: string,
    input: { name?: string; orgUnitId?: string | null },
  ) {
    return client.hostGroup.update({ where: { id }, data: input });
  }

  createOrgUnit(
    client: TenantPrismaClient,
    input: { name: string; parentId?: string | null },
  ) {
    return client.orgUnit.create({
      data: { name: input.name, parentId: input.parentId ?? null },
    });
  }

  /** Refuses a parent that is the unit itself or one of its descendants. */
  async updateOrgUnit(
    client: TenantPrismaClient,
    id: string,
    input: { name?: string; parentId?: string | null },
  ) {
    if (input.parentId) {
      for (
        let at: string | null = input.parentId;
        at !== null;
        at =
          (await client.orgUnit.findUnique({ where: { id: at } }))?.parentId ??
          null
      ) {
        if (at === id) throw new OrgUnitCycleError(id);
      }
    }
    return client.orgUnit.update({ where: { id }, data: input });
  }

  createApprovalRule(
    client: TenantPrismaClient,
    input: {
      hostGroupId?: string | null;
      hostnamePattern?: string | null;
      cidrs?: string[];
      requireTpm?: boolean;
      enabled?: boolean;
    },
  ) {
    assertCidrs(input.cidrs);
    return client.hostApprovalRule.create({
      data: {
        hostGroupId: input.hostGroupId ?? null,
        hostnamePattern: input.hostnamePattern ?? null,
        cidrs: input.cidrs ?? [],
        requireTpm: input.requireTpm ?? false,
        enabled: input.enabled ?? true,
      },
    });
  }

  updateApprovalRule(
    client: TenantPrismaClient,
    id: string,
    input: {
      hostnamePattern?: string | null;
      cidrs?: string[];
      requireTpm?: boolean;
      enabled?: boolean;
    },
  ) {
    assertCidrs(input.cidrs);
    return client.hostApprovalRule.update({ where: { id }, data: input });
  }
}

function assertCidrs(cidrs: string[] | undefined): void {
  const bad = (cidrs ?? []).filter((c) => !isValidCidr(c));
  if (bad.length > 0) throw new InvalidCidrError(bad.join(', '));
}
