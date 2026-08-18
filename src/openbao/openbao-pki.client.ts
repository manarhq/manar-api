import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/env.validation';

export interface SignVerbatimResult {
  /** PEM-encoded leaf certificate. */
  certificatePem: string;
  /** PEM-encoded issuing (intermediate) CA certificate. */
  issuingCaPem: string;
  /** Full PEM chain (intermediate + root) returned alongside the leaf. */
  caChainPem: string;
  /** Colon-separated hex serial, exactly as OpenBao returned it — pass verbatim back to `revoke`. */
  serialNumberColonHex: string;
}

/**
 * Thin wrapper around OpenBao's PKI secrets engine HTTP API
 * (https://openbao.org/api-docs/secret/pki/), covering exactly what
 * `CertificateAuthorityService` needs: sign a CSR *verbatim* (Manar has
 * already validated the CSR's subject/SAN before this is ever called — see
 * that service's doc comment for why `sign-verbatim` and not the
 * role-name-constrained `sign` endpoint), revoke a certificate by serial,
 * and fetch the issuing CA chain (for `POST /agents/enroll`'s response and
 * the mTLS listener's own trust bootstrapping).
 *
 * Authenticates with a deployment-wide bootstrap token
 * (`OPENBAO_TOKEN`) — see `openbao.config.ts`'s doc comment for why this
 * mirrors `KeycloakAdminClient`'s bootstrap-admin pattern rather than a
 * per-tenant credential.
 */
@Injectable()
export class OpenBaoPkiClient {
  private readonly logger = new Logger(OpenBaoPkiClient.name);
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly intermediatePath: string;
  private readonly agentRole: string;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    this.baseUrl = configService.get('OPENBAO_ADDR', { infer: true });
    this.token = configService.get('OPENBAO_TOKEN', { infer: true });
    this.intermediatePath = configService.get('OPENBAO_PKI_INTERMEDIATE_PATH', {
      infer: true,
    });
    this.agentRole = configService.get('OPENBAO_PKI_AGENT_ROLE', {
      infer: true,
    });
  }

  /**
   * Signs a CSR *verbatim* — OpenBao uses exactly the subject/SANs present
   * in `csrPem`, ignoring the role's `allowed_domains`/`allow_*` name
   * constraints. This is deliberate: `CertificateAuthorityService` has
   * already validated the CSR's SAN against the enrolling agent's expected
   * identifier *before* this method is ever called, which is the actual
   * security boundary (see that service). The role still governs TTL
   * ceiling and key-usage constraints. `ttl` is capped by the role's
   * `max_ttl` (see deploy/openbao-init.mjs) — OpenBao itself enforces
   * this, this method just passes the caller's requested value through.
   */
  async signVerbatim(csrPem: string, ttl: string): Promise<SignVerbatimResult> {
    const response = await this.request<{
      certificate: string;
      issuing_ca: string;
      ca_chain: string[];
      serial_number: string;
    }>('POST', `${this.intermediatePath}/sign-verbatim/${this.agentRole}`, {
      csr: csrPem,
      ttl,
    });

    return {
      certificatePem: response.certificate,
      issuingCaPem: response.issuing_ca,
      caChainPem: response.ca_chain.join('\n'),
      serialNumberColonHex: response.serial_number,
    };
  }

  /**
   * Revokes a certificate by serial number (colon-separated hex, OpenBao's
   * canonical format — see `AgentCertificate.serialNumber`'s storage
   * format in `certificate-authority.service.ts` for how a `X509Certificate`
   * -derived serial gets converted back to this format before calling
   * here). Idempotent from OpenBao's own perspective: revoking an
   * already-revoked serial is not an error.
   */
  async revoke(serialNumberColonHex: string): Promise<void> {
    await this.request('POST', `${this.intermediatePath}/revoke`, {
      serial_number: serialNumberColonHex,
    });
  }

  /**
   * Fetches the issuing CA's full trust chain (intermediate + root) as PEM
   * — an unauthenticated OpenBao PKI endpoint (the CA certificate is
   * public by definition). Used by `POST /agents/enroll`'s response so an
   * enrolling agent can pin the chain it should trust.
   */
  async getCaChainPem(): Promise<string> {
    const response = await fetch(
      `${this.baseUrl}/v1/${this.intermediatePath}/ca_chain`,
    );
    if (!response.ok) {
      throw new Error(
        `Failed to fetch OpenBao intermediate CA chain (HTTP ${response.status})`,
      );
    }
    return response.text();
  }

  private async request<T>(
    method: 'GET' | 'POST',
    apiPath: string,
    body?: unknown,
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}/v1/${apiPath}`, {
      method,
      headers: {
        'X-Vault-Token': this.token,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      this.logger.error(
        `OpenBao API ${method} ${apiPath} failed: HTTP ${response.status}`,
      );
      // Deliberately does not include the request body in the thrown error
      // (it may contain a CSR) — the response text is OpenBao's own error
      // message, never caller-supplied secret material.
      throw new Error(
        `OpenBao API ${method} ${apiPath} failed with HTTP ${response.status}${
          text ? `: ${text}` : ''
        }`,
      );
    }

    const json = (await response.json()) as { data: T };
    return json.data;
  }
}
