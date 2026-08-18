import { generateAgentCsr } from './csr';
import {
  buildAgentIdentifier,
  parseEnrollmentTokenParts,
} from './enrollment-token';
import type { AgentIdentity, IdentityStore } from './identity-store';

export interface ManarAgentOptions {
  /** Base URL of manar-api's human-facing HTTP surface (e.g. http://localhost:3000) -- NOT the mTLS listener, which an unenrolled agent has no certificate to reach yet. */
  endpoint: string;
  identityStore: IdentityStore;
}

interface EnrollResponseBody {
  certificate: string;
  caChain: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
}

/**
 * Minimal Phase 4 agent SDK (Section 68's full ergonomics -- task fetch,
 * execute, delegate -- arrive with later phases that add the server
 * capabilities behind them). This phase ships exactly one operation:
 * enrollment.
 *
 * ```ts
 * const manar = new ManarAgent({ endpoint, identityStore });
 * await manar.enroll(enrollmentToken);
 * ```
 */
export class ManarAgent {
  private readonly endpoint: string;
  private readonly identityStore: IdentityStore;

  constructor(options: ManarAgentOptions) {
    this.endpoint = options.endpoint.replace(/\/+$/, '');
    this.identityStore = options.identityStore;
  }

  /**
   * Generates a keypair + CSR *locally* (the private key never leaves
   * this process, and is never included in any request -- only the CSR,
   * which carries the public key half, is transmitted), exchanges the
   * one-time enrollment token for a signed certificate via
   * `POST /agents/enroll`, and stores the resulting identity via
   * `identityStore`. Throws if the token is invalid/used/expired, or if
   * the server rejects the CSR (both surface as an `Error` with the
   * server's response message -- see `postEnroll`).
   */
  async enroll(enrollmentToken: string): Promise<AgentIdentity> {
    const tokenParts = parseEnrollmentTokenParts(enrollmentToken);
    if (!tokenParts) {
      throw new Error('Malformed enrollment token');
    }

    const identifier = buildAgentIdentifier(
      tokenParts.tenantSlug,
      tokenParts.agentSlug,
    );
    const { csrPem, privateKeyPem } = await generateAgentCsr(identifier);

    const response = await this.postEnroll(enrollmentToken, csrPem);

    const identity: AgentIdentity = {
      certificatePem: response.certificate,
      caChainPem: response.caChain,
      privateKeyPem,
      enrolledAt: new Date().toISOString(),
    };

    await this.identityStore.save(identity);

    return identity;
  }

  /** Loads the previously-enrolled identity from `identityStore`, or `null` if this agent has never enrolled. */
  async loadIdentity(): Promise<AgentIdentity | null> {
    return this.identityStore.load();
  }

  private async postEnroll(
    token: string,
    csr: string,
  ): Promise<EnrollResponseBody> {
    const response = await fetch(`${this.endpoint}/agents/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, csr }),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(
        `Enrollment failed: HTTP ${response.status}${text ? `: ${text}` : ''}`,
      );
    }

    return (await response.json()) as EnrollResponseBody;
  }
}
