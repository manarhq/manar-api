import { createHash } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
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
 * 4. the Host is created, or merged by `machineId` across the whole tenant
 *    (VDI), and audited in the same transaction. Status comes from the
 *    approval rules for a new machine, and again whenever a known machine
 *    shows a different key (its old certificates are revoked) or a key from
 *    another group (it moves): only the same key keeps an approval;
 * 5. a host certificate is issued for `host://<tenantSlug>/<machineId>`.
 * A rejected or revoked machine stays so in every group and gets nothing.
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
    const keyFingerprint = createHash('sha256')
      .update(
        Buffer.from(
          new x509.Pkcs10CertificateRequest(input.csr).publicKey.rawData,
        ),
      )
      .digest('hex');

    const client = await this.tenants.getClient(tenant.id);
    const key = await this.keys.consume(client, input.installKey, input.ip);

    const { host, publish } = await client.$transaction(async (tx) => {
      const existing = await tx.host.findUnique({
        where: { machineId: input.machineId },
      });
      if (
        existing &&
        (existing.status === 'REVOKED' || existing.status === 'REJECTED')
      ) {
        throw new HostRefusedError(`host ${existing.id} is ${existing.status}`);
      }
      const keyChanged =
        existing !== null && existing.keyFingerprint !== keyFingerprint;
      const moved =
        existing !== null && existing.hostGroupId !== key.hostGroupId;
      const decideAgain = existing === null || keyChanged || moved;
      const rule = !decideAgain
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
      const decided = rule
        ? {
            status: 'APPROVED' as const,
            approvedBy: `rule:${rule.id}`,
            approvedAt: new Date(),
          }
        : { status: 'PENDING' as const, approvedBy: null, approvedAt: null };
      if (keyChanged) {
        // One machine, one key: the previous key's certificates stop now.
        await tx.hostCertificate.updateMany({
          where: { hostId: existing.id, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }
      const saved = existing
        ? await tx.host.update({
            where: { id: existing.id },
            data: {
              hostGroupId: key.hostGroupId,
              hostname: input.hostname,
              os: input.os,
              keyType: input.keyType,
              keyFingerprint,
              registeredFromIp: input.ip,
              lastSeenAt: new Date(),
              ...(decideAgain ? decided : {}),
            },
          })
        : await tx.host.create({
            data: {
              hostGroupId: key.hostGroupId,
              machineId: input.machineId,
              hostname: input.hostname,
              os: input.os,
              keyType: input.keyType,
              keyFingerprint,
              registeredFromIp: input.ip,
              lastSeenAt: new Date(),
              ...decided,
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
          keyChanged,
          movedFromGroupId: moved ? existing.hostGroupId : null,
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
