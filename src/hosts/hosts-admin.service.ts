import { Injectable } from '@nestjs/common';
import type {
  Host,
  HostStatus,
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { CertificateAuthorityService } from '../agents/certificate-authority.service';
import { EntitlementsService } from '../billing/entitlements.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES, type AuditActor } from '../audit/audit-event-types';
import {
  cursorWhereClause,
  toCursorPage,
  type CursorPage,
  type DecodedCursor,
} from '../common/pagination/cursor-pagination';
import { ruleHasVerifiedCondition } from './host-approval';
import { normalizeDn } from './adcs/ou.util';
import { isValidCidr } from './install-key.util';
import { InvalidCidrError } from './install-keys.service';
import { latestTamper, type TamperInfo } from './tamper';

export class HostNotFoundError extends Error {}

/** Standing secret-vault grants of a device end with it (revoked, removed or moved). */
async function withdrawVaultGrants(
  tx: Prisma.TransactionClient,
  hostId: string,
  by: string,
  now: Date,
): Promise<void> {
  await tx.secretVaultAccess.updateMany({
    where: {
      hostId,
      status: { in: ['ALLOW_8H', 'ALLOW_ALWAYS'] },
      withdrawnAt: null,
    },
    data: { withdrawnAt: now, withdrawnBy: by },
  });
}
/** The requested change isn't allowed from the host's current status. */
export class HostTransitionError extends Error {}
/** An auto-approval rule needs at least one verified condition (F2b, docs/hosts.md). */
export class UnverifiedRuleError extends Error {
  constructor() {
    super(
      'a rule needs at least one verified condition: an address range, requireAdcs, adOuDn or requireTpm (attested); a hostname pattern is self-reported',
    );
  }
}
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
    private readonly entitlements: EntitlementsService,
  ) {}

  async listHosts(
    client: TenantPrismaClient,
    input: {
      status?: HostStatus;
      hostGroupId?: string;
      limit: number;
      cursor?: DecodedCursor;
    },
  ): Promise<CursorPage<Host & { tamper: TamperInfo | null }>> {
    const page = await client.host
      .findMany({
        where: {
          // Removed devices only when asked for by status.
          status: input.status ?? { not: 'REMOVED' },
          ...(input.hostGroupId ? { hostGroupId: input.hostGroupId } : {}),
          ...cursorWhereClause('createdAt', input.cursor),
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: input.limit + 1,
      })
      .then((rows) => toCursorPage(rows, input.limit, (r) => r.createdAt));
    const tampered = await latestTamper(
      client,
      page.items.map((h) => h.id),
    );
    return {
      ...page,
      items: page.items.map((h) => ({
        ...h,
        tamper: tampered.get(h.id) ?? null,
      })),
    };
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
        const updated = await this.writeIfUnchanged(tx, current, {
          pendingKeyFingerprint: null,
          pendingHostGroupId: null,
          ...(approve
            ? {
                keyFingerprint: current.pendingKeyFingerprint,
                // A new key has not passed TPM attestation.
                tpmVerified: false,
                tpmEkFingerprint: null,
                hostGroupId: current.pendingHostGroupId ?? current.hostGroupId,
                status: 'APPROVED' as const,
                approvedBy: actor.id,
                approvedAt: new Date(),
              }
            : {}),
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
      // REJECTED -> APPROVED adds a device back to the count (PENDING and APPROVED are the
      // counted states), so it takes the same locked cap check as a new registration.
      if (decision === 'approve' && current.status === 'REJECTED') {
        await this.entitlements.assertWithinLocked(
          tx,
          tenantId,
          'devices',
          () =>
            tx.host.count({
              where: { status: { in: ['PENDING', 'APPROVED'] } },
            }),
        );
      }
      if (decision === 'revoke')
        await withdrawVaultGrants(tx, hostId, actor.id, new Date());
      const updated = await this.writeIfUnchanged(tx, current, {
        status: rule.to,
        // Revoking or rejecting also drops any rekey waiting for approval.
        ...(decision !== 'approve'
          ? { pendingKeyFingerprint: null, pendingHostGroupId: null }
          : {}),
        ...(decision === 'approve'
          ? { approvedBy: actor.id, approvedAt: new Date() }
          : {}),
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

  /**
   * "Remove device" (unenrol): revokes the host's certificates and retires its record (status
   * REMOVED). The row is kept, not deleted: sessions, approvals, events and AI usage point at it
   * and stay readable under "Removed devices". The device is told on its next call (410
   * device_removed) and stops protecting. Re-installing the machine enrols it again: within
   * RESTORE_WINDOW_MS as this same record, later as a new one (HostsService). Open approvals
   * expire and "approve for 8 hours" grants are revoked. Removing an already-removed host only
   * retries the certificate revocation (a double click, or OpenBao was down). Audited in the
   * same transaction.
   */
  async remove(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    hostId: string,
  ): Promise<void> {
    const host = await client.host.findUnique({ where: { id: hostId } });
    if (!host) throw new HostNotFoundError(hostId);
    if (host.status !== 'REMOVED') {
      await this.retire(client, tenantId, actor, host, null);
    }
    // After the status change, so a certificate issued meanwhile is caught too (registration
    // re-reads the host after signing). Marked revoked locally first; OpenBao follows.
    await this.ca.revokeHostCertificates(client, hostId);
  }

  /**
   * The device moved itself to another workspace (`POST /host/v1/moved`, signed by its own
   * certificate): removed here with reason `moved`, so this workspace shows "moved" instead of an
   * approved device that went quiet. Same steps as Remove device.
   */
  async markMoved(
    client: TenantPrismaClient,
    tenantId: string,
    hostId: string,
  ): Promise<void> {
    const host = await client.host.findUnique({ where: { id: hostId } });
    if (!host) throw new HostNotFoundError(hostId);
    if (host.status !== 'REMOVED') {
      await this.retire(
        client,
        tenantId,
        { type: 'system', id: 'system:device-moved' },
        host,
        'moved',
      );
    }
    await this.ca.revokeHostCertificates(client, hostId);
  }

  private async retire(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    host: Host,
    reason: 'moved' | null,
  ): Promise<void> {
    const hostId = host.id;
    const now = new Date();
    const publish = await client.$transaction(async (tx) => {
      // The same row lock registration takes: the two never interleave for one machine.
      await tx.$queryRaw`SELECT 1 FROM "hosts" WHERE "id" = ${hostId} FOR UPDATE`;
      const { count } = await tx.host.updateMany({
        where: { id: hostId, status: { not: 'REMOVED' } },
        data: {
          status: 'REMOVED',
          removedAt: now,
          removedReason: reason,
          adcsDnsName: null,
          pendingKeyFingerprint: null,
          pendingHostGroupId: null,
        },
      });
      if (count === 0) return null; // a concurrent remove won
      // Revoked in the same transaction as the status change; OpenBao follows after commit.
      await tx.hostCertificate.updateMany({
        where: { hostId, revokedAt: null },
        data: { revokedAt: now },
      });
      await tx.hostApproval.updateMany({
        where: { hostId, status: 'PENDING' },
        data: { status: 'EXPIRED' },
      });
      await tx.approvalAllowGrant.updateMany({
        where: { hostId, revokedAt: null },
        data: { revokedAt: now },
      });
      await withdrawVaultGrants(tx, hostId, actor.id, now);
      return this.audit.recordInTransaction(tx, tenantId, {
        eventType:
          reason === 'moved'
            ? AUDIT_EVENT_TYPES.HOST_MOVED
            : AUDIT_EVENT_TYPES.HOST_REMOVED,
        actor,
        data: { hostId, machineId: host.machineId, from: host.status },
      });
    });
    publish?.();
  }

  /**
   * Writes only if the host is still in the state the decision was made
   * from: a concurrent decision that committed first (a revoke, say) is
   * never overwritten; this one fails instead.
   */
  private async writeIfUnchanged(
    tx: Prisma.TransactionClient,
    current: Host,
    data: Prisma.HostUpdateManyMutationInput,
  ): Promise<Host> {
    const { count } = await tx.host.updateMany({
      where: {
        id: current.id,
        status: current.status,
        pendingKeyFingerprint: current.pendingKeyFingerprint,
      },
      data,
    });
    if (count === 0) {
      throw new HostTransitionError(
        `host ${current.id} changed while this decision was made`,
      );
    }
    return tx.host.findUniqueOrThrow({ where: { id: current.id } });
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

  async createApprovalRule(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: {
      hostGroupId?: string | null;
      hostnamePattern?: string | null;
      cidrs?: string[];
      requireTpm?: boolean;
      requireAdcs?: boolean;
      adOuDn?: string | null;
      enabled?: boolean;
    },
  ) {
    assertCidrs(input.cidrs);
    assertOuDn(input.adOuDn);
    assertGuard({
      cidrs: input.cidrs ?? [],
      requireTpm: input.requireTpm ?? false,
      requireAdcs: input.requireAdcs ?? false,
      adOuDn: input.adOuDn ?? null,
    });
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
            requireAdcs: input.requireAdcs ?? false,
            adOuDn: input.adOuDn ?? null,
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

  async updateApprovalRule(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
    input: {
      hostnamePattern?: string | null;
      cidrs?: string[];
      requireTpm?: boolean;
      requireAdcs?: boolean;
      adOuDn?: string | null;
      enabled?: boolean;
    },
  ) {
    assertCidrs(input.cidrs);
    assertOuDn(input.adOuDn);
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.HOST_APPROVAL_RULE_CHANGED,
      async (tx) => {
        const before = await tx.hostApprovalRule.findUnique({ where: { id } });
        // The guard applies to the rule as it will be, not to the patch alone.
        if (before) {
          assertGuard({
            cidrs: input.cidrs ?? before.cidrs,
            requireTpm: input.requireTpm ?? before.requireTpm,
            requireAdcs: input.requireAdcs ?? before.requireAdcs,
            adOuDn: input.adOuDn === undefined ? before.adOuDn : input.adOuDn,
          });
        }
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

function assertGuard(
  rule: Parameters<typeof ruleHasVerifiedCondition>[0],
): void {
  if (!ruleHasVerifiedCondition(rule)) throw new UnverifiedRuleError();
}

function assertOuDn(dn: string | null | undefined): void {
  if (dn && normalizeDn(dn) === null) {
    throw new InvalidCidrError('adOuDn is not a valid DN');
  }
}
