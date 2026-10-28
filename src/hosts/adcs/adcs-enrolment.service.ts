import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as x509 from '@peculiar/x509';
import type { AppConfig } from '../../config/env.validation';
import { ssrfPolicyFromConfig } from '../../common/ssrf/ssrf.config';
import { CertificateAuthorityService } from '../../agents/certificate-authority.service';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { HostsService, type RegisterHostResult } from '../hosts.service';
import { TpmAttestationService } from '../tpm/tpm-attestation.service';
import { AdcsDirectoryService } from './adcs-directory.service';
import {
  CertChainError,
  EKU_CLIENT_AUTH,
  parsePem,
  validateChain,
} from './cert-chain.util';
import { verifyProof, spkiFingerprint } from './computer-proof.util';
import { checkRevocation, fetchCrlHttp } from './crl.util';

/** The computer certificate was not accepted. One generic 401 to the caller; `reason` goes to the log. */
export class AdcsCertificateRejectedError extends Error {
  constructor(readonly reason: string) {
    super(`computer certificate rejected: ${reason}`);
  }
}

export const CRL_FETCHER = Symbol('CRL_FETCHER');
export type CrlFetcher = (url: string) => Promise<Uint8Array>;

export interface RegisterWithCertificateInput {
  tenantSlug: string;
  /** PEM: the computer certificate first, then any intermediates. */
  certificates: string[];
  csr: string;
  machineId: string;
  os: string;
  keyType: 'TPM' | 'SOFTWARE';
  /** ISO time the proof was made. */
  timestamp: string;
  /** Base64 signature by the computer certificate's key (computer-proof.util). */
  signature: string;
  tpmChallengeId?: string;
  ip: string;
}

/**
 * Key-less enrolment of a domain-joined machine (docs/hosts.md). Order:
 * tenant, proof of possession and CSR, chain to the tenant's customer CA
 * (validity, EKU clientAuth, path rules), then (only for a chained
 * certificate) the CRL, then AD for the OU, then the TPM challenge. A
 * certificate that is wrong is refused; one that merely could not be
 * fully verified registers PENDING and is never auto-approved.
 */
@Injectable()
export class AdcsEnrolmentService {
  private readonly logger = new Logger(AdcsEnrolmentService.name);
  private readonly fetchCrl: CrlFetcher;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly ca: CertificateAuthorityService,
    private readonly directory: AdcsDirectoryService,
    private readonly tpm: TpmAttestationService,
    private readonly hosts: HostsService,
    config: ConfigService<AppConfig, true>,
    @Optional() @Inject(CRL_FETCHER) crlFetcher?: CrlFetcher,
  ) {
    const policy = ssrfPolicyFromConfig(config);
    this.fetchCrl = crlFetcher ?? ((url) => fetchCrlHttp(url, { policy }));
  }

  async register(
    input: RegisterWithCertificateInput,
  ): Promise<RegisterHostResult> {
    const tenant = await this.control.tenant.findUnique({
      where: { slug: input.tenantSlug },
    });
    if (!tenant || tenant.status !== 'ACTIVE') {
      throw new AdcsCertificateRejectedError('unknown tenant');
    }
    const client = await this.tenants.getClient(tenant.id);
    const identifier = `host://${tenant.slug}/${input.machineId}`;
    await this.ca.assertCsrNames(input.csr, identifier);
    const keyFingerprint = spkiFingerprint(
      new Uint8Array(
        new x509.Pkcs10CertificateRequest(input.csr).publicKey.rawData,
      ),
    );

    const [leafPem, ...intermediates] = input.certificates;
    if (!leafPem) throw new AdcsCertificateRejectedError('no certificate');
    let leaf: x509.X509Certificate;
    try {
      leaf = parsePem(leafPem);
    } catch {
      throw new AdcsCertificateRejectedError('unparseable');
    }
    if (
      !verifyProof(
        leaf,
        {
          tenantSlug: tenant.slug,
          machineId: input.machineId,
          csrKeyFingerprint: keyFingerprint,
          timestamp: input.timestamp,
        },
        input.signature,
      )
    ) {
      throw new AdcsCertificateRejectedError('proof of possession failed');
    }

    const cas = await client.adcsTrustedCa.findMany();
    let chain: x509.X509Certificate[];
    try {
      ({ chain } = await validateChain({
        leafPem,
        intermediatesPem: intermediates,
        anchorsPem: cas.map((c) => c.certPem),
        requireEku: EKU_CLIENT_AUTH,
      }));
    } catch (error) {
      throw new AdcsCertificateRejectedError(
        error instanceof CertChainError ? error.reason : 'invalid',
      );
    }

    // The CRL URL comes from the presented certificate; it is fetched only
    // now, after the certificate chained to this tenant's CA.
    const revocation = await checkRevocation(leaf, chain[1]!, this.fetchCrl);
    if (revocation === 'revoked') {
      throw new AdcsCertificateRejectedError('revoked');
    }

    const dnsName = leaf
      .getExtension(x509.SubjectAlternativeNameExtension)
      ?.names.items.find((n) => n.type === 'dns')?.value;
    if (!dnsName) throw new AdcsCertificateRejectedError('no DNS name');

    const ou = await this.directory.resolve(client, tenant.id, dnsName);
    const adDn = ou.state === 'resolved' ? ou.dn : null;
    const hostGroupId = ou.state === 'resolved' ? ou.hostGroupId : null;

    const settings = await client.adcsSettings.findUnique({
      where: { id: 'default' },
    });
    if (!settings) {
      throw new AdcsCertificateRejectedError('AD CS enrolment not configured');
    }

    const redeemed = input.tpmChallengeId
      ? await this.tpm.redeem(
          client,
          input.tpmChallengeId,
          input.machineId,
          keyFingerprint,
        )
      : null;
    if (input.tpmChallengeId && !redeemed) {
      this.logger.warn(
        `TPM challenge ${input.tpmChallengeId} not redeemable for tenant ${tenant.id}`,
      );
    }

    const certVerified = revocation === 'good';
    if (!certVerified || hostGroupId === null) {
      this.logger.warn(
        `ADCS registration for tenant ${tenant.id} left PENDING: revocation=${revocation} ad=${ou.state}`,
      );
    }
    return this.hosts.completeRegistration({
      tenant: { id: tenant.id, slug: tenant.slug },
      client,
      identifier,
      csr: input.csr,
      keyFingerprint,
      machineId: input.machineId,
      hostname: dnsName,
      os: input.os,
      keyType: input.keyType,
      ip: input.ip,
      method: 'ADCS',
      hostGroupId,
      defaultHostGroupId: settings.defaultHostGroupId,
      installKeyId: null,
      // Doubt about the certificate or the OU: a person decides.
      autoApprove: certVerified && hostGroupId !== null,
      verified: { adcs: certVerified, adDn, tpm: redeemed !== null },
      tpmEkFingerprint: redeemed?.ekFingerprint ?? null,
      adcs: { dnsName, adDn, revocation, adState: ou.state },
    });
  }
}
