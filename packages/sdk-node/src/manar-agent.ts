import { generateAgentCsr } from './csr';
import {
  buildAgentIdentifier,
  parseEnrollmentTokenParts,
} from './enrollment-token';
import type { AgentIdentity, IdentityStore } from './identity-store';
import { mtlsRequestJson } from './mtls-http';

export interface ManarAgentOptions {
  /** Base URL of manar-api's human-facing HTTP surface (e.g. http://localhost:3000) -- NOT the mTLS listener, which an unenrolled agent has no certificate to reach yet. */
  endpoint: string;
  identityStore: IdentityStore;
  /**
   * Base URL of manar-api's agent-facing mTLS HTTPS listener (e.g.
   * https://127.0.0.1:3443 -- see docs/agent-identity.md). Required for
   * `authorize()`/`delegateTask()` (Phase 5), not for `enroll()` (an
   * unenrolled agent has no certificate yet to authenticate an mTLS
   * request with in the first place). Optional at construction time so
   * `enroll()`-only callers don't need to supply a value they don't use.
   */
  mtlsEndpoint?: string;
}

interface EnrollResponseBody {
  certificate: string;
  caChain: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
}

export interface AuthorizeRequest {
  taskId: string;
  toolId: string;
  actionId: string;
  resource: string;
}

export type AuthorizeDecision =
  { decision: 'ALLOW' } | { decision: 'DENY'; reason: string };

export interface DelegateTaskGrant {
  toolId: string;
  actionId: string;
}

export interface DelegateTaskResourceSelector {
  toolId: string;
  pattern: string;
}

export interface DelegateTaskRequest {
  childAgentSlug: string;
  childAgentDisplayName?: string;
  name: string;
  description?: string;
  allowedToolActions: DelegateTaskGrant[];
  allowedResourceSelectors: DelegateTaskResourceSelector[];
  forbiddenActions?: DelegateTaskGrant[];
  /** ISO-8601 -- clamped server-side to the parent task's own `expiresAt` if omitted or later, see docs/task-delegation.md. */
  expiresAt?: string;
  maxExecutions?: number | null;
  riskCeiling?: number;
}

export interface DelegateTaskResponse {
  childTask: {
    id: string;
    status: string;
    assignedAgentId: string;
    parentTaskId: string | null;
    expiresAt: string;
  };
  childAgent: { id: string; slug: string; identifier: string };
  /** The child agent's one-time enrollment token -- pass this to a *separate* `ManarAgent.enroll()` call for the child, the same as any human-created agent's token (see docs/task-delegation.md). */
  enrollmentToken: { token: string; expiresAt: string };
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
  private readonly mtlsEndpoint: string | undefined;
  private readonly identityStore: IdentityStore;

  constructor(options: ManarAgentOptions) {
    this.endpoint = options.endpoint.replace(/\/+$/, '');
    this.mtlsEndpoint = options.mtlsEndpoint?.replace(/\/+$/, '');
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

  /**
   * `POST /agent/v1/authorize` over mTLS using this agent's enrolled
   * identity (Phase 5). Always resolves to a `{ decision }` object, never
   * throws for a DENY -- a DENY is a legitimate, expected answer, not a
   * transport/request error (this mirrors `AuthorizeController`'s own
   * "never map a DENY to an HTTP error status" contract). Throws only for
   * a genuine transport failure, a malformed request, or if this agent has
   * never enrolled.
   */
  async authorize(request: AuthorizeRequest): Promise<AuthorizeDecision> {
    const identity = await this.requireIdentity();
    return mtlsRequestJson<AuthorizeDecision>({
      endpoint: this.requireMtlsEndpoint(),
      path: '/agent/v1/authorize',
      method: 'POST',
      body: request,
      identity,
    });
  }

  /**
   * `POST /agent/v1/tasks/:id/delegate` over mTLS using this agent's
   * enrolled identity -- this agent must be `taskId`'s assigned agent.
   * Throws if the server rejects the delegation (e.g. the requested grants
   * exceed this agent's own task's effective authority -- Section 20's
   * non-amplification invariant), with the server's own error message.
   */
  async delegateTask(
    taskId: string,
    request: DelegateTaskRequest,
  ): Promise<DelegateTaskResponse> {
    const identity = await this.requireIdentity();
    return mtlsRequestJson<DelegateTaskResponse>({
      endpoint: this.requireMtlsEndpoint(),
      path: `/agent/v1/tasks/${encodeURIComponent(taskId)}/delegate`,
      method: 'POST',
      body: request,
      identity,
    });
  }

  private async requireIdentity(): Promise<AgentIdentity> {
    const identity = await this.identityStore.load();
    if (!identity) {
      throw new Error(
        'No enrolled identity found in identityStore -- call enroll() first',
      );
    }
    return identity;
  }

  private requireMtlsEndpoint(): string {
    if (!this.mtlsEndpoint) {
      throw new Error(
        'ManarAgent was constructed without mtlsEndpoint -- required for authorize()/delegateTask()',
      );
    }
    return this.mtlsEndpoint;
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
