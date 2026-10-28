import { createHash } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import type {
  Host,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { CertificateAuthorityService } from '../agents/certificate-authority.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { matchApprovalRule, type VerifiedFacts } from './host-approval';
import { TpmAttestationService } from './tpm/tpm-attestation.service';
import { tenantSlugOf } from './install-key.util';
import {
  InstallKeyInvalidError,
  InstallKeysService,
} from './install-keys.service';

/** The machine is known and was rejected or revoked: no new certificate. */
export class HostRefusedError extends Error {}

/**
 * A known machine showed a different key, or a key of another group. The
 * request is recorded for an admin; nothing about the machine changes and no
 * certificate is issued until the rekey is approved.
 */
export class HostRekeyPendingError extends Error {}

export interface RegisterHostInput {
  installKey: string;
  csr: string;
  machineId: string;
  hostname: string;
  os: string;
  keyType: 'TPM' | 'SOFTWARE';
  /** A verified TPM challenge (docs/hosts.md); without one the TPM claim is not trusted. */
  tpmChallengeId?: string;
  /** The address the request came from (the server's view, not the client's claim). */
  ip: string;
}

/** What the registration core needs; both entry points build it after their own checks. */
export interface CompleteRegistrationInput {
  tenant: { id: string; slug: string };
  client: TenantPrismaClient;
  identifier: string;
  csr: string;
  keyFingerprint: string;
  machineId: string;
  hostname: string;
  os: string;
  /** What the installer reports; shown as TPM only when `verified.tpm`. */
  keyType: 'TPM' | 'SOFTWARE';
  ip: string;
  method: 'INSTALL_KEY' | 'ADCS';
  /** The group decided by the key or by a verified OU; null: not decided. */
  hostGroupId: string | null;
  /** Used when `hostGroupId` is null (a new ADCS host whose OU is unknown). */
  defaultHostGroupId: string;
  installKeyId: string | null;
  /** False: the host is PENDING whatever the rules say (doubt about identity). */
  autoApprove: boolean;
  verified: VerifiedFacts;
  tpmEkFingerprint: string | null;
  adcs: {
    dnsName: string;
    adDn: string | null;
    revocation: 'good' | 'unknown';
    adState: string;
  } | null;
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
 * 4. the Host is created (status from the approval rules), or, for a
 *    machine already known in the tenant with the same key and group,
 *    merged (VDI) keeping its status; audited in the same transaction. A
 *    different key, or a key from another group, changes nothing: it is
 *    recorded as a pending rekey for an admin (no certificate meanwhile), so
 *    an install key alone can neither take over nor disturb a machine;
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
    private readonly tpm: TpmAttestationService,
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
    const redeemed = input.tpmChallengeId
      ? await this.tpm.redeem(
          client,
          input.tpmChallengeId,
          input.machineId,
          keyFingerprint,
        )
      : null;
    return this.completeRegistration({
      tenant: { id: tenant.id, slug },
      client,
      identifier,
      csr: input.csr,
      keyFingerprint,
      machineId: input.machineId,
      hostname: input.hostname,
      os: input.os,
      keyType: input.keyType,
      ip: input.ip,
      method: 'INSTALL_KEY',
      hostGroupId: key.hostGroupId,
      defaultHostGroupId: key.hostGroupId,
      installKeyId: key.id,
      autoApprove: true,
      verified: { adcs: false, adDn: null, tpm: redeemed !== null },
      tpmEkFingerprint: redeemed?.ekFingerprint ?? null,
      adcs: null,
    });
  }

  /**
   * The shared registration core (install key and computer certificate):
   * creates or merges the Host, applies approval rules (only for facts the
   * server verified), audits in the same transaction, issues the host
   * certificate. See the class comment for the order and the rekey rules.
   */
  async completeRegistration(
    ctx: CompleteRegistrationInput,
  ): Promise<RegisterHostResult> {
    const { client, tenant, keyFingerprint, identifier } = ctx;
    const input = ctx;
    const adcs = ctx.method === 'ADCS';
    const keyType = ctx.verified.tpm ? 'TPM' : ctx.keyType;

    const { host, publish, rekeyPending } = await client.$transaction(
      async (tx) => {
        const existing = await tx.host.findUnique({
          where: { machineId: input.machineId },
        });
        if (
          existing &&
          (existing.status === 'REVOKED' || existing.status === 'REJECTED')
        ) {
          throw new HostRefusedError(
            `host ${existing.id} is ${existing.status}`,
          );
        }
        // One certificate identity, one host: a computer certificate cannot
        // register a second machineId, nor take over another host's machineId.
        if (ctx.adcs) {
          const holder = await tx.host.findUnique({
            where: { adcsDnsName: ctx.adcs.dnsName },
          });
          if (holder && holder.machineId !== input.machineId) {
            throw new HostRefusedError(
              `certificate identity already belongs to host ${holder.id}`,
            );
          }
          if (
            existing?.enrolmentMethod === 'ADCS' &&
            existing.adcsDnsName !== ctx.adcs.dnsName
          ) {
            throw new HostRefusedError(
              `host ${existing.id} is bound to another certificate identity`,
            );
          }
        }
        // A known computer-certificate host follows its OU (when AD was read);
        // anything else must keep the group its key was issued for.
        const followsOu = adcs && existing?.enrolmentMethod === 'ADCS';
        const targetGroupId = followsOu
          ? (ctx.hostGroupId ?? existing.hostGroupId)
          : (ctx.hostGroupId ?? ctx.defaultHostGroupId);
        if (
          existing &&
          (existing.keyFingerprint !== keyFingerprint ||
            // A host enrolled another way has no certificate identity: an
            // admin decides whether this certificate may take it over.
            (adcs && existing.enrolmentMethod !== 'ADCS') ||
            (!followsOu && existing.hostGroupId !== targetGroupId))
        ) {
          // One pending rekey at a time: a second one never replaces it, so
          // an admin approves exactly the key they looked at.
          const conflictsWithPending = existing.pendingKeyFingerprint !== null;
          if (!conflictsWithPending) {
            await tx.host.update({
              where: { id: existing.id },
              data: {
                pendingKeyFingerprint: keyFingerprint,
                pendingHostGroupId: targetGroupId,
              },
            });
          }
          const requested = await this.audit.recordInTransaction(
            tx,
            tenant.id,
            {
              eventType: AUDIT_EVENT_TYPES.HOST_REKEY_REQUESTED,
              actor: { type: 'system', id: 'system:host-registration' },
              data: {
                hostId: existing.id,
                installKeyId: ctx.installKeyId,
                keyFingerprint,
                keyChanged: existing.keyFingerprint !== keyFingerprint,
                toHostGroupId: targetGroupId,
                ip: input.ip,
                // One rekey waits at a time; a later one is recorded, never applied.
                conflictsWithPending,
              },
            },
          );
          return { host: existing, publish: requested, rekeyPending: true };
        }
        const rule =
          existing || !ctx.autoApprove
            ? null
            : matchApprovalRule(
                await tx.hostApprovalRule.findMany({
                  where: {
                    enabled: true,
                    OR: [{ hostGroupId: null }, { hostGroupId: targetGroupId }],
                  },
                  orderBy: { createdAt: 'asc' },
                }),
                {
                  hostGroupId: targetGroupId,
                  hostname: input.hostname,
                  ip: input.ip,
                  verified: ctx.verified,
                },
              );
        const adFacts = ctx.adcs
          ? {
              enrolmentMethod: 'ADCS',
              adcsDnsName: ctx.adcs.dnsName,
              ...(ctx.adcs.adDn
                ? { adDn: ctx.adcs.adDn, adDnCheckedAt: new Date() }
                : {}),
            }
          : {};
        const tpmFacts = ctx.verified.tpm
          ? { tpmVerified: true, tpmEkFingerprint: ctx.tpmEkFingerprint }
          : {};
        const moved =
          existing !== null && existing.hostGroupId !== targetGroupId;
        const saved = existing
          ? await tx.host.update({
              where: { id: existing.id },
              data: {
                hostname: input.hostname,
                os: input.os,
                keyType,
                registeredFromIp: input.ip,
                lastSeenAt: new Date(),
                hostGroupId: targetGroupId,
                ...(followsOu ? adFacts : {}),
                ...tpmFacts,
              },
            })
          : await tx.host.create({
              data: {
                hostGroupId: targetGroupId,
                machineId: input.machineId,
                hostname: input.hostname,
                os: input.os,
                keyType,
                keyFingerprint,
                registeredFromIp: input.ip,
                lastSeenAt: new Date(),
                ...adFacts,
                ...tpmFacts,
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
            installKeyId: ctx.installKeyId,
            enrolmentMethod: ctx.method,
            merged: existing !== null,
            status: saved.status,
            approvalRuleId: rule?.id ?? null,
            keyType: saved.keyType,
            tpmVerified: saved.tpmVerified,
            ...(ctx.adcs
              ? {
                  adcsDnsName: ctx.adcs.dnsName,
                  revocation: ctx.adcs.revocation,
                  adState: ctx.adcs.adState,
                }
              : {}),
            ip: input.ip,
          },
        });
        if (moved) {
          // Followed its OU to another group: its own record, same transaction.
          const groupMoved = await this.audit.recordInTransaction(
            tx,
            tenant.id,
            {
              eventType: AUDIT_EVENT_TYPES.HOST_GROUP_MOVED,
              actor: { type: 'system', id: 'system:host-registration' },
              data: {
                hostId: saved.id,
                fromHostGroupId: existing.hostGroupId,
                toHostGroupId: targetGroupId,
                adDn: ctx.adcs?.adDn ?? null,
                source: 'registration',
              },
            },
          );
          return {
            host: saved,
            publish: () => {
              done();
              groupMoved();
            },
            rekeyPending: false,
          };
        }
        return { host: saved, publish: done, rekeyPending: false };
      },
    );
    publish();
    if (rekeyPending) {
      throw new HostRekeyPendingError(
        `host ${host.id}: a different key or group waits for an admin`,
      );
    }

    const issued = await this.ca.issueHostCertificate(
      client,
      { id: host.id, identifier },
      input.csr,
    );
    // The host may have been revoked, rejected or rekeyed while the CA was
    // signing: a certificate that no longer matches is revoked at once.
    const now = await client.host.findUnique({ where: { id: host.id } });
    if (
      !now ||
      now.status === 'REVOKED' ||
      now.status === 'REJECTED' ||
      now.keyFingerprint !== keyFingerprint
    ) {
      await this.ca.revokeHostCertificateSerial(client, issued.serialNumber);
      throw new HostRefusedError(`host ${host.id} changed during registration`);
    }
    return {
      hostId: host.id,
      status: host.status,
      certificatePem: issued.certificatePem,
      caChainPem: issued.caChainPem,
    };
  }
}
