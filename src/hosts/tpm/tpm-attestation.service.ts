import {
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../../generated/tenant-client/client';
import { AuditService } from '../../audit/audit.service';
import {
  AUDIT_EVENT_TYPES,
  type AuditActor,
} from '../../audit/audit-event-types';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import {
  CertChainError,
  parsePem,
  validateChain,
} from '../adcs/cert-chain.util';
import {
  makeCredential,
  parseTpmtPublic,
  TPMA_NON_EXPORTABLE,
  TpmStructureError,
  tpmName,
} from './tpm-structures';

/** The attestation request is not acceptable. The message is for the log; callers answer one generic 400/401. */
export class TpmAttestationError extends Error {}

const CHALLENGE_TTL_MS = 10 * 60_000;
const MAX_OPEN_CHALLENGES = 500;
const sha256 = (b: Uint8Array | string) =>
  createHash('sha256').update(b).digest('hex');
const SYSTEM: AuditActor = { type: 'system', id: 'system:tpm-attestation' };

export interface TpmChallengeInput {
  tenantSlug: string;
  machineId: string;
  /** PEM of the endorsement key certificate, then its intermediates. */
  ekCertificates: string[];
  /** Base64 marshalled TPMT_PUBLIC of the host key (the key the CSR is for). */
  hostKeyPublic: string;
}

/**
 * Server side of TPM credential activation (docs/hosts.md):
 * 1. `challenge`: the EK certificate must chain to a TPM root the tenant
 *    configured; the host key must be non-exportable (fixedTPM, fixedParent,
 *    sensitiveDataOrigin). The server wraps a random secret for that EK and
 *    that key's name (MakeCredential) and keeps only the secret's hash.
 * 2. `activate`: only a TPM holding that EK and that key can unwrap the
 *    secret; the host returns it. Three wrong answers kill the challenge.
 * 3. `redeem` (at registration): the challenge must be verified, unexpired,
 *    unused, for this machine and for exactly the key in the CSR.
 */
@Injectable()
export class TpmAttestationService {
  private readonly logger = new Logger(TpmAttestationService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  private async tenantClient(slug: string) {
    const tenant = await this.control.tenant.findUnique({ where: { slug } });
    if (!tenant || tenant.status !== 'ACTIVE') {
      throw new TpmAttestationError('unknown tenant');
    }
    return { tenant, client: await this.tenants.getClient(tenant.id) };
  }

  async challenge(input: TpmChallengeInput) {
    const { tenant, client } = await this.tenantClient(input.tenantSlug);
    const [ekPem, ...chainPem] = input.ekCertificates;
    if (!ekPem) throw new TpmAttestationError('no EK certificate');
    const roots = await client.tpmTrustRoot.findMany();
    let ek;
    try {
      ek = (
        await validateChain({
          leafPem: ekPem,
          intermediatesPem: chainPem,
          anchorsPem: roots.map((r) => r.certPem),
        })
      ).leaf;
    } catch (error) {
      throw new TpmAttestationError(
        `EK certificate refused: ${error instanceof CertChainError ? error.reason : 'invalid'}`,
      );
    }
    const ekKey = createPublicKey({
      key: Buffer.from(ek.publicKey.rawData),
      format: 'der',
      type: 'spki',
    });
    const modulus = ekKey.asymmetricKeyDetails?.modulusLength ?? 0;
    if (ekKey.asymmetricKeyType !== 'rsa' || modulus < 2048) {
      throw new TpmAttestationError('only RSA EK of 2048 bits or more');
    }
    let tpmPublic: Buffer;
    let keyFingerprint: string;
    try {
      tpmPublic = Buffer.from(input.hostKeyPublic, 'base64');
      const parsed = parseTpmtPublic(tpmPublic);
      if ((parsed.attributes & TPMA_NON_EXPORTABLE) !== TPMA_NON_EXPORTABLE) {
        throw new TpmAttestationError('host key is not TPM-resident');
      }
      keyFingerprint = sha256(parsed.spki);
    } catch (error) {
      if (error instanceof TpmAttestationError) throw error;
      if (error instanceof TpmStructureError) {
        throw new TpmAttestationError(`bad host key: ${error.message}`);
      }
      throw error;
    }
    const open = await client.tpmChallenge.count({
      where: { expiresAt: { gt: new Date() }, consumedAt: null },
    });
    if (open >= MAX_OPEN_CHALLENGES) {
      throw new TpmAttestationError('too many open challenges');
    }
    const secret = randomBytes(32);
    const { credentialBlob, encryptedSecret } = makeCredential({
      ekPublicKey: ekKey,
      akName: tpmName(tpmPublic),
      secret,
    });
    const row = await client.tpmChallenge.create({
      data: {
        machineId: input.machineId,
        keyFingerprint,
        ekFingerprint: sha256(Buffer.from(ek.rawData)),
        secretHash: sha256(secret),
        expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
      },
    });
    this.logger.log(`TPM challenge ${row.id} issued for tenant ${tenant.id}`);
    return {
      challengeId: row.id,
      credentialBlob: credentialBlob.toString('base64'),
      encryptedSecret: encryptedSecret.toString('base64'),
      expiresAt: row.expiresAt,
    };
  }

  /** True when the returned secret is the one wrapped for this challenge. */
  async activate(input: {
    tenantSlug: string;
    challengeId: string;
    secret: string;
  }): Promise<boolean> {
    const { tenant, client } = await this.tenantClient(input.tenantSlug);
    const row = await client.tpmChallenge.findUnique({
      where: { id: input.challengeId },
    });
    if (
      !row ||
      row.consumedAt ||
      row.verifiedAt ||
      row.attemptsLeft <= 0 ||
      row.expiresAt <= new Date()
    ) {
      return false;
    }
    // Spend an attempt first, atomically, so guesses cannot race the counter.
    const spent = await client.tpmChallenge.updateMany({
      where: { id: row.id, attemptsLeft: { gt: 0 }, verifiedAt: null },
      data: { attemptsLeft: { decrement: 1 } },
    });
    if (spent.count !== 1) return false;
    const given = Buffer.from(
      sha256(Buffer.from(input.secret, 'base64')),
      'hex',
    );
    const want = Buffer.from(row.secretHash, 'hex');
    if (given.length !== want.length || !timingSafeEqual(given, want)) {
      if (row.attemptsLeft - 1 <= 0) {
        this.logger.warn(`TPM challenge ${row.id} exhausted`);
      }
      return false;
    }
    const { count, publish } = await client.$transaction(async (tx) => {
      const done = await tx.tpmChallenge.updateMany({
        where: { id: row.id, verifiedAt: null, consumedAt: null },
        data: { verifiedAt: new Date() },
      });
      const p = await this.audit.recordInTransaction(tx, tenant.id, {
        eventType: AUDIT_EVENT_TYPES.HOST_TPM_VERIFIED,
        actor: SYSTEM,
        data: {
          challengeId: row.id,
          machineId: row.machineId,
          ekFingerprint: row.ekFingerprint,
          keyFingerprint: row.keyFingerprint,
        },
      });
      return { count: done.count, publish: p };
    });
    if (count === 1) publish();
    return count === 1;
  }

  /**
   * At registration: marks the challenge used and returns the EK fingerprint
   * only if it was verified for this machine and this exact key. Null in
   * every other case (the host then registers without TPM verification).
   */
  async redeem(
    client: TenantPrismaClient,
    challengeId: string,
    machineId: string,
    keyFingerprint: string,
  ): Promise<{ ekFingerprint: string } | null> {
    const row = await client.tpmChallenge.findUnique({
      where: { id: challengeId },
    });
    if (!row) return null;
    const used = await client.tpmChallenge.updateMany({
      where: {
        id: challengeId,
        machineId,
        keyFingerprint,
        verifiedAt: { not: null },
        consumedAt: null,
        expiresAt: { gt: new Date() },
      },
      data: { consumedAt: new Date() },
    });
    return used.count === 1 ? { ekFingerprint: row.ekFingerprint } : null;
  }

  // Trust roots (admin, audited).

  listRoots(client: TenantPrismaClient) {
    return client.tpmTrustRoot.findMany({ orderBy: { createdAt: 'asc' } });
  }

  async addRoot(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: { label: string; certPem: string },
  ) {
    const cert = parsePem(input.certPem);
    if (cert.notAfter < new Date()) {
      throw new TpmAttestationError('certificate is expired');
    }
    return this.audited(client, tenantId, actor, async (tx) => {
      const row = await tx.tpmTrustRoot.create({
        data: {
          label: input.label,
          certPem: cert.toString('pem'),
          subject: cert.subject,
          fingerprint: sha256(Buffer.from(cert.rawData)),
          notAfter: cert.notAfter,
          createdBy: actor.id,
        },
      });
      return { row, data: { rootId: row.id, before: null, after: row } };
    });
  }

  async removeRoot(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
  ) {
    return this.audited(client, tenantId, actor, async (tx) => {
      const row = await tx.tpmTrustRoot.delete({ where: { id } });
      return { row, data: { rootId: id, before: row, after: null } };
    });
  }

  private async audited<T>(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    change: (
      tx: Prisma.TransactionClient,
    ) => Promise<{ row: T; data: unknown }>,
  ): Promise<T> {
    const { row, publish } = await client.$transaction(async (tx) => {
      const { row: r, data } = await change(tx);
      const p = await this.audit.recordInTransaction(tx, tenantId, {
        eventType: AUDIT_EVENT_TYPES.TPM_TRUST_ROOT_CHANGED,
        actor,
        data,
      });
      return { row: r, publish: p };
    });
    publish();
    return row;
  }
}
