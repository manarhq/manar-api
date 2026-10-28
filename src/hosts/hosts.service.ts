import { Injectable } from '@nestjs/common';
import type { Host } from '../generated/tenant-client/client';
import { CertificateAuthorityService } from '../agents/certificate-authority.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { matchApprovalRule } from './host-approval';
import { tenantSlugOf } from './install-key.util';
import {
  InstallKeyInvalidError,
  InstallKeysService,
} from './install-keys.service';

/** The machine is known and was rejected or revoked: no new certificate. */
export class HostRefusedError extends Error {}

export interface RegisterHostInput {
  installKey: string;
  csr: string;
  machineId: string;
  hostname: string;
  os: string;
  keyType: 'TPM' | 'SOFTWARE';
  /** The address the request came from (the server's view, not the client's claim). */
  ip: string;
}

export interface RegisterHostResult {
  hostId: string;
  status: Host['status'];
  certificatePem: string;
  caChainPem: string;
}

/**
 * Host registration (docs/hosts.md). Order matters:
 * 1. the key's prefix names the tenant (a host never picks its own);
 * 2. the CSR is checked before anything is spent or created;
 * 3. one key use is taken;
 * 4. the Host is created, or merged by `(hostGroupId, machineId)` (VDI),
 *    with status from the approval rules for a new machine, and audited in
 *    the same transaction;
 * 5. a host certificate is issued for `host://<tenantSlug>/<machineId>`.
 * A rejected or revoked machine stays so and gets nothing.
 */
@Injectable()
export class HostsService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly keys: InstallKeysService,
    private readonly audit: AuditService,
    private readonly ca: CertificateAuthorityService,
  ) {}

  async register(input: RegisterHostInput): Promise<RegisterHostResult> {
    const slug = tenantSlugOf(input.installKey);
    if (!slug) throw new InstallKeyInvalidError();
    const tenant = await this.control.tenant.findUnique({ where: { slug } });
    if (!tenant || tenant.status !== 'ACTIVE')
      throw new InstallKeyInvalidError();
    const identifier = `host://${slug}/${input.machineId}`;
    await this.ca.assertCsrNames(input.csr, identifier);

    const client = await this.tenants.getClient(tenant.id);
    const key = await this.keys.consume(client, input.installKey, input.ip);

    const { host, publish } = await client.$transaction(async (tx) => {
      const existing = await tx.host.findUnique({
        where: {
          hostGroupId_machineId: {
            hostGroupId: key.hostGroupId,
            machineId: input.machineId,
          },
        },
      });
      if (
        existing &&
        (existing.status === 'REVOKED' || existing.status === 'REJECTED')
      ) {
        throw new HostRefusedError(`host ${existing.id} is ${existing.status}`);
      }
      const rule = existing
        ? null
        : matchApprovalRule(
            await tx.hostApprovalRule.findMany({
              where: {
                enabled: true,
                OR: [{ hostGroupId: null }, { hostGroupId: key.hostGroupId }],
              },
              orderBy: { createdAt: 'asc' },
            }),
            {
              hostGroupId: key.hostGroupId,
              hostname: input.hostname,
              ip: input.ip,
              keyType: input.keyType,
            },
          );
      const saved = existing
        ? await tx.host.update({
            where: { id: existing.id },
            data: {
              hostname: input.hostname,
              os: input.os,
              keyType: input.keyType,
              registeredFromIp: input.ip,
              lastSeenAt: new Date(),
            },
          })
        : await tx.host.create({
            data: {
              hostGroupId: key.hostGroupId,
              machineId: input.machineId,
              hostname: input.hostname,
              os: input.os,
              keyType: input.keyType,
              registeredFromIp: input.ip,
              lastSeenAt: new Date(),
              ...(rule
                ? {
                    status: 'APPROVED' as const,
                    approvedBy: `rule:${rule.id}`,
                    approvedAt: new Date(),
                  }
                : {}),
            },
          });
      const done = await this.audit.recordInTransaction(tx, tenant.id, {
        eventType: AUDIT_EVENT_TYPES.HOST_REGISTERED,
        actor: { type: 'system', id: 'system:host-registration' },
        data: {
          hostId: saved.id,
          hostGroupId: saved.hostGroupId,
          installKeyId: key.id,
          merged: existing !== null,
          status: saved.status,
          approvalRuleId: rule?.id ?? null,
          keyType: saved.keyType,
          ip: input.ip,
        },
      });
      return { host: saved, publish: done };
    });
    publish();

    const issued = await this.ca.issueHostCertificate(
      client,
      { id: host.id, identifier },
      input.csr,
    );
    return {
      hostId: host.id,
      status: host.status,
      certificatePem: issued.certificatePem,
      caChainPem: issued.caChainPem,
    };
  }
}
