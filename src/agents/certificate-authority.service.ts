import { webcrypto } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { OpenBaoPkiClient } from '../openbao/openbao-pki.client';
import { CsrValidationError } from './certificate-authority.errors';
import {
  normalizeSerialNumber,
  toColonSeparatedHex,
} from './serial-number.util';

// @peculiar/x509 needs a WebCrypto provider; Node's own `crypto.webcrypto`
// is used everywhere else in this codebase reaches for crypto (see
// packages/sdk-node's identity store), so this is the same provider, not a
// polyfill.
x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export interface IssuedCertificate {
  certificatePem: string;
  /** Full PEM chain (intermediate + root) — returned to the enrolling agent so it can pin its trust anchor. */
  caChainPem: string;
  /** Canonical form: uppercase hex, no separators — see serial-number.util.ts. */
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
}

/**
 * OpenBao only *signs* certificates — Manar owns every policy decision
 * around agent workload identity (Section 16 of the master prompt):
 *
 *   1. Validates the CSR's Subject Alternative Name against the enrolling
 *      agent's expected `agent://<tenantSlug>/<slug>` identifier — this
 *      check runs entirely inside this service, *before* OpenBao is ever
 *      called, and is the actual security boundary. OpenBao's
 *      `sign-verbatim` (see OpenBaoPkiClient) signs *exactly* whatever
 *      subject/SAN the CSR contains with no name-constraint enforcement of
 *      its own by design — trusting it to reject a mismatched CSR would be
 *      trusting a system that was never asked to check in the first place.
 *   2. Enforces a short leaf-certificate TTL
 *      (`AGENT_LEAF_CERTIFICATE_TTL`, 24h — see that constant's doc
 *      comment for why).
 *   3. Calls OpenBao's `sign-verbatim` against the intermediate CA's agent
 *      signing role.
 *   4. Persists the issued certificate's metadata (never its private key,
 *      which never even exists here — see packages/sdk-node) to
 *      `AgentCertificate`.
 *   5. `revoke(...)` calls OpenBao's revoke endpoint and updates local
 *      state so `AgentMtlsGuard` can reject the very next request using
 *      that certificate — immediate revocation is a mandatory invariant
 *      (Section 71), not a best-effort one.
 */
@Injectable()
export class CertificateAuthorityService {
  private readonly logger = new Logger(CertificateAuthorityService.name);

  /**
   * Short-lived by design — an agent identity certificate compromised
   * outside of Manar's own revocation path (e.g. exfiltrated from a
   * compromised host) self-expires quickly. 24h was chosen as a concrete,
   * documented value per the design spec ("e.g. 24h"); certificate
   * auto-renewal before expiry is explicitly out of scope this phase (a
   * later phase's SDK responsibility). Must match `LEAF_TTL` in
   * deploy/openbao-init.mjs (the signing role's own `max_ttl` ceiling).
   */
  static readonly AGENT_LEAF_CERTIFICATE_TTL = '24h';

  constructor(private readonly openBao: OpenBaoPkiClient) {}

  /**
   * Validates `csrPem`'s SAN against `agent.identifier`, signs it via
   * OpenBao, and persists the resulting `AgentCertificate` row. Throws
   * `CsrValidationError` (never reaches OpenBao) if the CSR's subject
   * doesn't match — the caller (`AgentsService.enroll`) is responsible for
   * translating that into an HTTP 400.
   */
  async issueCertificate(
    tenantClient: TenantPrismaClient,
    agent: { id: string; identifier: string },
    csrPem: string,
  ): Promise<IssuedCertificate> {
    await this.validateCsr(csrPem, agent.identifier, [agent.identifier]);

    const signed = await this.openBao.signVerbatim(
      csrPem,
      CertificateAuthorityService.AGENT_LEAF_CERTIFICATE_TTL,
    );

    const issuedCert = new x509.X509Certificate(signed.certificatePem);
    const serialNumber = normalizeSerialNumber(issuedCert.serialNumber);

    await tenantClient.agentCertificate.create({
      data: {
        agentId: agent.id,
        serialNumber,
        subject: issuedCert.subject,
        notBefore: issuedCert.notBefore,
        notAfter: issuedCert.notAfter,
      },
    });

    return {
      certificatePem: signed.certificatePem,
      caChainPem: signed.caChainPem,
      serialNumber,
      notBefore: issuedCert.notBefore,
      notAfter: issuedCert.notAfter,
    };
  }

  /**
   * Checks a CSR before anything is created for it: proof of possession and
   * exactly one URI SAN equal to `identifier`. Throws `CsrValidationError`.
   */
  async assertCsrNames(csrPem: string, identifier: string): Promise<void> {
    await this.validateCsr(csrPem, identifier, hostCommonNames(identifier));
  }

  /**
   * Hosts (docs/hosts.md): the same issuance as agents, for a machine whose
   * CSR names `host://<tenantSlug>/<machineId>`; stored as a `HostCertificate`.
   */
  async issueHostCertificate(
    tenantClient: TenantPrismaClient,
    host: { id: string; identifier: string },
    csrPem: string,
  ): Promise<IssuedCertificate> {
    await this.validateCsr(
      csrPem,
      host.identifier,
      hostCommonNames(host.identifier),
    );
    const signed = await this.openBao.signVerbatim(
      csrPem,
      CertificateAuthorityService.AGENT_LEAF_CERTIFICATE_TTL,
    );
    const issuedCert = new x509.X509Certificate(signed.certificatePem);
    const serialNumber = normalizeSerialNumber(issuedCert.serialNumber);
    await tenantClient.hostCertificate.create({
      data: {
        hostId: host.id,
        serialNumber,
        notBefore: issuedCert.notBefore,
        notAfter: issuedCert.notAfter,
      },
    });
    return {
      certificatePem: signed.certificatePem,
      caChainPem: signed.caChainPem,
      serialNumber,
      notBefore: issuedCert.notBefore,
      notAfter: issuedCert.notAfter,
    };
  }

  /** Hosts: revokes one certificate (locally first, then OpenBao). */
  async revokeHostCertificateSerial(
    tenantClient: TenantPrismaClient,
    serialNumber: string,
  ): Promise<void> {
    await tenantClient.hostCertificate.updateMany({
      where: { serialNumber, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    try {
      await this.openBao.revoke(toColonSeparatedHex(serialNumber));
      await tenantClient.hostCertificate.updateMany({
        where: { serialNumber },
        data: { caRevokedAt: new Date() },
      });
    } catch (error) {
      this.logger.error(
        `OpenBao revoke of host certificate ${serialNumber} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Hosts: marks every certificate of `hostId` revoked locally (enforced at
   * once), then asks OpenBao; OpenBao failures are logged, not thrown.
   */
  async revokeHostCertificates(
    tenantClient: TenantPrismaClient,
    hostId: string,
  ): Promise<void> {
    await tenantClient.hostCertificate.updateMany({
      where: { hostId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    // Every serial revoked here but not yet confirmed by OpenBao (also those
    // a previous call failed on).
    const owed = await tenantClient.hostCertificate.findMany({
      where: { hostId, revokedAt: { not: null }, caRevokedAt: null },
    });
    for (const cert of owed) {
      try {
        await this.openBao.revoke(toColonSeparatedHex(cert.serialNumber));
        await tenantClient.hostCertificate.update({
          where: { id: cert.id },
          data: { caRevokedAt: new Date() },
        });
      } catch (error) {
        this.logger.error(
          `OpenBao revoke of host certificate ${cert.serialNumber} failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  /**
   * Revokes every certificate for `agentId`, local state first: the
   * certificates' `revokedAt` and `Agent.status = REVOKED` are committed
   * before OpenBao is called. `AgentMtlsGuard` reads both from PostgreSQL on
   * every request, so the agent is blocked on its next request even when
   * OpenBao is down (Gate 0 finding S10: the old OpenBao-first order threw
   * before any local change and left the agent working).
   *
   * OpenBao is then asked to revoke each serial it has not yet confirmed
   * (`caRevokedAt` null). Failures are logged and counted, not thrown: the
   * enforcement already happened, and calling `revoke` again retries them.
   * Returns the number of serials still owed to OpenBao.
   */
  async revoke(
    tenantClient: TenantPrismaClient,
    agentId: string,
    reason: string,
  ): Promise<{ caRevocationPending: number }> {
    await tenantClient.$transaction([
      tenantClient.agentCertificate.updateMany({
        where: { agentId, revokedAt: null },
        data: { revokedAt: new Date(), revocationReason: reason },
      }),
      tenantClient.agent.update({
        where: { id: agentId },
        data: { status: 'REVOKED' },
      }),
    ]);

    const owed = await tenantClient.agentCertificate.findMany({
      where: { agentId, revokedAt: { not: null }, caRevokedAt: null },
    });

    let caRevocationPending = 0;
    for (const certificate of owed) {
      try {
        await this.openBao.revoke(
          toColonSeparatedHex(certificate.serialNumber),
        );
        await tenantClient.agentCertificate.update({
          where: { id: certificate.id },
          data: { caRevokedAt: new Date() },
        });
      } catch (error) {
        caRevocationPending++;
        this.logger.error(
          `OpenBao revoke failed for certificate ${certificate.serialNumber} of agent "${agentId}"; the agent is blocked locally, retry by revoking again: ${(error as Error).message}`,
        );
      }
    }

    this.logger.log(
      `Revoked agent "${agentId}" (${owed.length} certificate(s) sent to OpenBao, ${caRevocationPending} pending): ${reason}`,
    );
    return { caRevocationPending };
  }

  /**
   * Revokes one certificate, local state first (`AgentMtlsGuard` refuses it on its next request),
   * then OpenBao. An OpenBao failure is logged, not thrown; revoking the agent retries it.
   */
  async revokeCertificate(
    tenantClient: TenantPrismaClient,
    serialNumber: string,
    reason: string,
  ): Promise<void> {
    await tenantClient.agentCertificate.updateMany({
      where: { serialNumber, revokedAt: null },
      data: { revokedAt: new Date(), revocationReason: reason },
    });
    try {
      await this.openBao.revoke(toColonSeparatedHex(serialNumber));
      await tenantClient.agentCertificate.updateMany({
        where: { serialNumber },
        data: { caRevokedAt: new Date() },
      });
    } catch (error) {
      this.logger.error(
        `OpenBao revoke failed for certificate ${serialNumber}; it is refused locally: ${(error as Error).message}`,
      );
    }
  }

  /**
   * The actual security boundary (see class doc comment). Parses the CSR,
   * verifies its self-signature (proof that the requester actually holds
   * the private key matching the CSR's public key — without this, anyone
   * could submit a CSR naming someone else's public key), and requires
   * *exactly one* URI-type Subject Alternative Name that matches
   * `expectedIdentifier` character-for-character. The CSR's CN/subject
   * string is deliberately not enforced here — the SAN URI is the
   * authoritative identity (the same SPIFFE-style convention
   * `AgentMtlsGuard` reads back out of an issued certificate), a free-text
   * CN is not.
   *
   * The subject is pinned too, because `sign-verbatim` copies it into the
   * certificate and other services on the same PKI may read the CN: it must
   * be exactly one CN, and that CN one of `allowedCommonNames` (the full
   * identifier; for hosts also the bare machine id existing devices send, if
   * it is a hex or GUID machine id).
   */
  private async validateCsr(
    csrPem: string,
    expectedIdentifier: string,
    allowedCommonNames: string[],
  ): Promise<void> {
    let csr: x509.Pkcs10CertificateRequest;
    try {
      csr = new x509.Pkcs10CertificateRequest(csrPem);
    } catch (error) {
      throw new CsrValidationError(
        `Could not parse CSR as a PKCS#10 certificate request: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    // Proof of possession: the CSR is self-signed by the private key
    // matching its embedded public key. Without this check, a caller could
    // submit a CSR naming a public key it doesn't actually hold the
    // private half of.
    const signatureValid = await csr.verify();
    if (!signatureValid) {
      throw new CsrValidationError(
        'CSR signature does not verify against its own public key',
      );
    }

    const sanExtension = csr.extensions.find(
      (extension): extension is x509.SubjectAlternativeNameExtension =>
        extension instanceof x509.SubjectAlternativeNameExtension,
    );
    const names = sanExtension?.names.items ?? [];
    const uriNames = names
      .filter((name) => name.type === 'url')
      .map((name) => name.value);

    // OpenBao signs verbatim: any other name (DNS, IP, email) in the CSR
    // would end up in the certificate, so exactly one URI and nothing else.
    if (
      names.length !== 1 ||
      uriNames.length !== 1 ||
      uriNames[0] !== expectedIdentifier
    ) {
      throw new CsrValidationError(
        `CSR Subject Alternative Name (URI) does not match this agent's expected identifier. Expected exactly one URI SAN equal to "${expectedIdentifier}", got: ${JSON.stringify(uriNames)}`,
      );
    }

    const attributes = csr.subjectName
      .toJSON()
      .flatMap((rdn) =>
        Object.entries(rdn).flatMap(([type, values]) =>
          values.map((value) => ({ type, value })),
        ),
      );
    if (
      attributes.length !== 1 ||
      attributes[0]!.type !== 'CN' ||
      !allowedCommonNames.includes(attributes[0]!.value)
    ) {
      throw new CsrValidationError(
        `CSR subject must be exactly "CN=${expectedIdentifier}"`,
      );
    }
  }
}

/**
 * The bare machine ids a host CSR may carry as its CN, and nothing else: manar-edge's hashed id
 * (`m-` + 32 hex), a raw Linux machine-id (32 hex) or a Windows MachineGuid (a GUID). An
 * allowlist, so no hostname, address or service name can ever be a device certificate's CN.
 */
const BARE_MACHINE_ID =
  /^(?:m-[0-9a-f]{32}|[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

/** CNs a host CSR may carry: its full `host://` identifier, or its bare machine id if it is one of the forms above. */
function hostCommonNames(identifier: string): string[] {
  const machineId = identifier.slice(identifier.lastIndexOf('/') + 1);
  return BARE_MACHINE_ID.test(machineId)
    ? [identifier, machineId]
    : [identifier];
}
