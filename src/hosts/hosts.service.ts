import { ModuleRef } from '@nestjs/core';
import {
  PersonalTrialService,
  type DeviceFacts,
} from '../growth/personal-trial.service';
import { createHash } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import type {
  Host,
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { CertificateAuthorityService } from '../agents/certificate-authority.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { matchApprovalRule, type VerifiedFacts } from './host-approval';
import { EntitlementsService } from '../billing/entitlements.service';
import { TpmAttestationService } from './tpm/tpm-attestation.service';
import { normalizeInstallCode } from './install-code.util';
import { InstallCodesService } from './install-codes.service';
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
  /** Keycloak subject of whoever created the install key; null when unknown. */
  ownerSubject?: string | null;
  /** The install-key secret to use once, in the registration transaction, after the refusal and cap checks. */
  consumeSecret?: string;
  /** False: the host is PENDING whatever the rules say (doubt about identity). */
  autoApprove: boolean;
  /**
   * A personal workspace's own one-time Add-device code: the one person who could make the code
   * approves a new device, so it is APPROVED at once (audited as an approval). Never a machine
   * already known (re-install), and never for company workspaces, which wait for an approval
   * rule or an admin.
   */
  ownerApproves?: boolean;
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

/** `approvedBy` and audit actor for a personal workspace's device approved by its owner's code. */
const OWNER_APPROVER = 'system:personal-install-code';

/** A removed device that enrols again within this window comes back as the same record. */
export const RESTORE_WINDOW_MS = 30 * 24 * 3_600_000;

/**
 * Host registration (docs/hosts.md). Order matters:
 * 1. the key's prefix names the tenant (a host never picks its own);
 * 2. the CSR is checked before anything is spent or created;
 * 3. one key use is taken;
 * 4. the Host is created (status from the approval rules), or, for a
 *    machine already known in the tenant with the same key and group,
 *    merged (VDI) keeping its status; audited in the same transaction. A
 *    different key for a known machine never touches the known host (its key
 *    and certificates stay): it becomes a separate PENDING host flagged as a
 *    possible clone or re-install, which an admin (or in a personal
 *    workspace, its owner) approves or rejects. A key from another group is
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
    private readonly entitlements: EntitlementsService,
    private readonly codes: InstallCodesService,
    /** Optional: only the HTTP app has the launch offer (looked up lazily, never required). */
    private readonly moduleRef?: ModuleRef,
  ) {}

  async register(input: RegisterHostInput): Promise<RegisterHostResult> {
    // `installKey` is a `mik_<tenant>_...` key, or the short code of the "Add device" one-liner,
    // which stands for a key whose secret it is: the control DB maps its hash to the tenant.
    const code = normalizeInstallCode(input.installKey);
    let slug: string | null;
    let tenant;
    if (code) {
      const found = await this.codes.find(code);
      if (!found) throw new InstallKeyInvalidError();
      slug = found.tenantSlug;
      tenant = await this.control.tenant.findUnique({ where: { slug } });
    } else {
      slug = tenantSlugOf(input.installKey);
      if (!slug) throw new InstallKeyInvalidError();
      tenant = await this.control.tenant.findUnique({ where: { slug } });
    }
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
    const secret = code ?? input.installKey;
    // Look at the key without using it: everything that can refuse this machine (a revoked or
    // rejected record, the device cap) is checked first, inside the registration transaction,
    // and only then is the one use taken, so a refused install does not burn the code.
    let key;
    try {
      key = await this.keys.peek(client, secret, input.ip);
    } catch (error) {
      if (code && error instanceof InstallKeyInvalidError) {
        await this.codes.deleteByCode(code);
      }
      throw error;
    }
    const redeemed = input.tpmChallengeId
      ? await this.tpm.redeem(
          client,
          input.tpmChallengeId,
          input.machineId,
          keyFingerprint,
        )
      : null;
    const result = await this.completeRegistration({
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
      consumeSecret: secret,
      ownerSubject: await this.ownerSubjectOf(client, key.createdBy),
      autoApprove: true,
      ownerApproves: code !== null && tenant.kind === 'PERSONAL',
      verified: { adcs: false, adDn: null, tpm: redeemed !== null },
      tpmEkFingerprint: redeemed?.ekFingerprint ?? null,
      adcs: null,
    }).catch(async (error: unknown) => {
      // A spent, revoked or expired key leaves nothing behind that could resolve again.
      if (code && error instanceof InstallKeyInvalidError) {
        await this.codes.deleteByCode(code);
      }
      throw error;
    });
    if (code) await this.codes.deleteByCode(code); // used: one registration per code
    if (result.status === 'APPROVED')
      this.startTrial(tenant.id, {
        machineId: input.machineId,
        ekFingerprint: redeemed?.ekFingerprint ?? null,
        ip: input.ip,
      });
    return result;
  }

  /** A new personal workspace's first device starts its 14-day trial. Detached; it cannot fail the install. */
  private startTrial(tenantId: string, device: DeviceFacts): void {
    try {
      const trial = this.moduleRef?.get(PersonalTrialService, {
        strict: false,
      });
      void trial?.onDeviceRegistered(tenantId, device);
    } catch {
      // not in this app (worker, tests): no trial here
    }
  }

  private async ownerSubjectOf(
    client: TenantPrismaClient,
    userId: string,
  ): Promise<string | null> {
    const user = await client.userProfile.findUnique({ where: { id: userId } });
    return user?.keycloakSubject ?? null;
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
    // Stored as SOFTWARE unless TPM attestation passed; the installer's claim is not kept.
    const keyType = ctx.verified.tpm ? 'TPM' : 'SOFTWARE';

    const { host, publish, rekeyPending, reenrolled } =
      await client.$transaction(async (tx) => {
        // Serialises with "Remove device" (HostsAdminService.retire takes the same row lock), so a
        // removal and a registration of one machine never interleave.
        await tx.$queryRaw`SELECT 1 FROM "hosts" WHERE "machineId" = ${input.machineId} FOR UPDATE`;
        // The machine's original record (clones of it carry `cloneOfHostId`).
        const found = await tx.host.findFirst({
          where: { machineId: input.machineId, cloneOfHostId: null },
        });
        // A removed machine enrols as a new device would. Its owner re-installing it with an
        // install key within RESTORE_WINDOW_MS revives the old record (history continues), and
        // it waits PENDING for an admin. Anyone else, another enrolment method, or a later
        // install gets a new record; the old one keeps the history and gives up the machineId.
        let revive: Host | null = null;
        if (found?.status === 'REMOVED') {
          const removedAt = found.removedAt?.getTime() ?? 0;
          if (
            Date.now() - removedAt < RESTORE_WINDOW_MS &&
            ctx.method === 'INSTALL_KEY' &&
            found.enrolmentMethod === 'INSTALL_KEY' &&
            !!ctx.ownerSubject &&
            found.ownerSubject === ctx.ownerSubject
          ) {
            revive = found;
            // Certificates of the removed record never come back to life with it.
            await tx.hostCertificate.updateMany({
              where: { hostId: found.id, revokedAt: null },
              data: { revokedAt: new Date() },
            });
          } else {
            await tx.host.update({
              where: { id: found.id },
              data: { machineId: `removed:${found.id}` },
            });
          }
        }
        const known = found?.status === 'REMOVED' ? null : found;
        if (
          known &&
          (known.status === 'REVOKED' || known.status === 'REJECTED')
        ) {
          throw new HostRefusedError(`host ${known.id} is ${known.status}`);
        }
        // A new key for a known machine (founder decision, 4 Nov 2026): never a key swap on the
        // known host, whoever made the install key. It is its own device, PENDING, flagged as a
        // possible clone or re-install. The same key again merges into that device.
        let cloneOf: Host | null = null;
        let twin: Host | null = null;
        if (
          known &&
          ctx.method === 'INSTALL_KEY' &&
          known.keyFingerprint !== keyFingerprint
        ) {
          twin = await tx.host.findFirst({
            where: {
              machineId: input.machineId,
              keyFingerprint,
              cloneOfHostId: { not: null },
              status: { not: 'REMOVED' },
            },
          });
          if (twin && (twin.status === 'REVOKED' || twin.status === 'REJECTED'))
            throw new HostRefusedError(`host ${twin.id} is ${twin.status}`);
          if (!twin) cloneOf = known;
        }
        const existing = cloneOf ? null : (twin ?? known);
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
        // A new device counts against the plan, under a lock held until this transaction ends,
        // so N+1 parallel registrations cannot all pass. A known machine is not a new device.
        // This and the refusals above run BEFORE the install key is used.
        if (!existing) {
          await this.entitlements.assertWithinLocked(
            tx,
            tenant.id,
            'devices',
            () =>
              tx.host.count({
                where: { status: { in: ['PENDING', 'APPROVED'] } },
              }),
          );
        }
        if (ctx.consumeSecret) {
          await this.keys.consume(tx, ctx.consumeSecret, input.ip);
        }
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
          return {
            host: existing,
            publish: requested,
            rekeyPending: true,
            reenrolled: false,
          };
        }
        // A personal owner's own code approves a NEW device only. machineId is the installer's
        // claim, so a re-install of a known machine (new key) waits for the owner to confirm it.
        // A revived record and a possible clone always wait for a person: no owner or rule approval.
        const ownerApproved =
          !!ctx.ownerApproves &&
          ctx.autoApprove &&
          !existing &&
          !revive &&
          !cloneOf;
        const rule =
          existing || revive || cloneOf || !ctx.autoApprove || ownerApproved
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
        const fresh: Omit<Prisma.HostUncheckedCreateInput, 'machineId'> = {
          hostGroupId: targetGroupId,
          hostname: input.hostname,
          os: input.os,
          keyType,
          keyFingerprint,
          registeredFromIp: input.ip,
          lastSeenAt: new Date(),
          ownerSubject: ctx.ownerSubject ?? null,
          installKeyId: ctx.installKeyId,
          ...(cloneOf ? { cloneOfHostId: cloneOf.id } : {}),
          ...adFacts,
          ...tpmFacts,
          ...(rule || ownerApproved
            ? {
                status: 'APPROVED' as const,
                approvedBy: rule ? `rule:${rule.id}` : OWNER_APPROVER,
                approvedAt: new Date(),
              }
            : {}),
        };
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
                installKeyId: ctx.installKeyId,
                ...(followsOu ? adFacts : {}),
                ...tpmFacts,
              },
            })
          : revive
            ? await tx.host.update({
                where: { id: revive.id },
                // Everything a new host would start with; the id (and so the history) stays.
                data: {
                  status: 'PENDING',
                  approvedBy: null,
                  approvedAt: null,
                  removedAt: null,
                  pendingKeyFingerprint: null,
                  pendingHostGroupId: null,
                  enrolmentMethod: 'INSTALL_KEY',
                  adcsDnsName: null,
                  adDn: null,
                  adDnCheckedAt: null,
                  tpmVerified: false,
                  tpmEkFingerprint: null,
                  ...fresh,
                },
              })
            : await tx.host.create({
                data: {
                  machineId: input.machineId,
                  ...fresh,
                  // The machine's learning-mode anchor follows the machine, not the row: a removed
                  // or cloned record's first approval carries over, so re-enrolling cannot restart
                  // the 7 days. Null when the machine was never approved.
                  firstApprovedAt: found?.firstApprovedAt ?? undefined,
                },
              });
        const registered = await this.audit.recordInTransaction(tx, tenant.id, {
          eventType: AUDIT_EVENT_TYPES.HOST_REGISTERED,
          actor: { type: 'system', id: 'system:host-registration' },
          data: {
            hostId: saved.id,
            hostGroupId: saved.hostGroupId,
            installKeyId: ctx.installKeyId,
            enrolmentMethod: ctx.method,
            merged: existing !== null,
            restored: revive !== null,
            reenrolled: revive !== null,
            possibleCloneOf: cloneOf?.id ?? null,
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
        // Approved by the workspace owner's own code: the same event an admin's approval writes.
        const approved = ownerApproved
          ? await this.audit.recordInTransaction(tx, tenant.id, {
              eventType: AUDIT_EVENT_TYPES.HOST_APPROVED,
              actor: { type: 'system', id: OWNER_APPROVER },
              data: {
                hostId: saved.id,
                from: 'PENDING',
                to: 'APPROVED',
                reason: 'personal_workspace_install_code',
                ownerSubject: ctx.ownerSubject ?? null,
                installKeyId: ctx.installKeyId,
              },
            })
          : null;
        // Possible clone or re-install: its own event, so an alert can key on it.
        const cloned = cloneOf
          ? await this.audit.recordInTransaction(tx, tenant.id, {
              eventType: AUDIT_EVENT_TYPES.HOST_POSSIBLE_CLONE,
              actor: { type: 'system', id: 'system:host-registration' },
              data: {
                hostId: saved.id,
                cloneOfHostId: cloneOf.id,
                machineId: input.machineId,
                installKeyId: ctx.installKeyId,
                keyFingerprint,
                ip: input.ip,
              },
            })
          : null;
        const done = () => {
          registered();
          approved?.();
          cloned?.();
        };
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
            reenrolled: revive !== null,
          };
        }
        return {
          host: saved,
          publish: done,
          rekeyPending: false,
          reenrolled: revive !== null,
        };
      });
    publish();
    if (rekeyPending) {
      throw new HostRekeyPendingError(
        `host ${host.id}: a different key or group waits for an admin`,
      );
    }

    // A revived removed record: the certificates it still had stop now.
    if (reenrolled) await this.ca.revokeHostCertificates(client, host.id);
    const issued = await this.ca.issueHostCertificate(
      client,
      { id: host.id, identifier },
      input.csr,
    );
    // The host may have been revoked, rejected, removed or rekeyed while the CA was
    // signing: a certificate that no longer matches is revoked at once.
    const now = await client.host.findUnique({ where: { id: host.id } });
    if (
      !now ||
      (now.status !== 'PENDING' && now.status !== 'APPROVED') ||
      now.removedAt !== null ||
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
