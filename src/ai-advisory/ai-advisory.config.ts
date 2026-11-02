import { z } from 'zod';

/**
 * Phase 10b (AI Advisory Pipeline Integration) — connection/resilience
 * settings for `AiAdvisoryClient`, the only thing in this codebase that
 * ever calls `manar-ai`'s gRPC `AnalysisService` (see
 * docs/ai-security-model.md). Kept alongside the `ai-advisory` module
 * rather than growing `AppConfigSchema` into a god-schema — see
 * `src/authorization/openfga.config.ts` for the established pattern.
 */
export const AiAdvisoryConfigSchema = z.object({
  /**
   * `host:port` of manar-ai's gRPC `AnalysisService` (plaintext this phase
   * — see docs/ai-security-model.md's "mTLS status" section, which mirrors
   * manar-ai's own deliberate scope call). Matches
   * `deploy/docker-compose.yml`'s `manar-ai` service's host-mapped gRPC
   * port.
   */
  AI_ADVISORY_GRPC_TARGET: z.string().min(1).default('localhost:50051'),

  /**
   * Release 2026-11-11 — mTLS to manar-ai's `AnalysisService`.
   *
   * manar-ai now binds `add_secure_port` with
   * `ssl_server_credentials(require_client_auth=True)` and a peer-identity
   * interceptor, and **refuses to bind a plaintext port at all** when its
   * own `ENVIRONMENT` is `staging` or `production`. It still binds
   * plaintext for `local`/`development`/`test`, logging a warning, so the
   * existing developer stack keeps working unchanged.
   *
   * This flag therefore defaults to `false`: turning it on is a deployment
   * decision that has to be made in step with manar-ai's own configuration
   * and with the PKI that issues both sides' certificates. What must never
   * happen is this client silently falling back to plaintext against a
   * server that expects mTLS — that surfaces as a connection failure, which
   * the circuit breaker then reports as an unavailable advisory service,
   * which is the correct fail-secure behaviour but an unhelpful diagnostic.
   * Hence the explicit flag and the all-or-nothing validation below.
   *
   * Certificate requirements, from manar-ai's side of the contract
   * (`manar-ai/docs/grpc-typescript-client.md`):
   *
   *  - The client certificate's CN or DNS SAN must be `manar-api` (this
   *    HTTP process) or `manar-api-worker` (the Temporal worker). Any other
   *    identity gets `PERMISSION_DENIED` even with a CA-issued certificate
   *    — possession of a valid certificate is authentication, not
   *    authorization.
   *  - Both certificates must be issued by the same internal CA that
   *    manar-ai loads as its client CA. manar-ai does not consult the
   *    system trust store, so a publicly-trusted certificate will not work.
   *  - manar-ai's server certificate must carry a SAN covering the address
   *    dialled here.
   *
   * Paths mirror manar-ai's own mount convention (`/etc/manar/tls/...`) so
   * the PKI plumbing stays symmetric across the two services.
   */
  AI_ADVISORY_TLS_ENABLED: z.enum(['true', 'false']).default('false'),
  /** PEM bundle of the CA that issued manar-ai's server certificate. */
  AI_ADVISORY_TLS_CA_FILE: z.string().min(1).optional(),
  /** This service's own client certificate (CN/SAN `manar-api` or `manar-api-worker`). */
  AI_ADVISORY_TLS_CERT_FILE: z.string().min(1).optional(),
  /** Private key for `AI_ADVISORY_TLS_CERT_FILE`. */
  AI_ADVISORY_TLS_KEY_FILE: z.string().min(1).optional(),

  /**
   * Per-RPC deadline in milliseconds, applied only to the **hot lane**
   * (`AnalyzeRisk`/`AnalyzePromptInjection`/`AnalyzeDlp` — inline on the
   * authorization/tool-invocation path). It does **not** apply to the
   * three long-form generation RPCs (`SummarizeIncident`/`SuggestPolicy`/
   * `InvestigateAudit`) — those use `AI_ADVISORY_LONGFORM_TIMEOUT_MS`
   * instead; see `AiAdvisoryClient`'s doc comment for why the two lanes
   * are deliberately independent. Short (Section 80: an AI outage must add
   * no more than this configured amount of latency, never hang the
   * pipeline waiting on a slow/unreachable model backend) — see
   * `AiAdvisoryClient`'s doc comment for why 2s is the chosen default.
   */
  AI_ADVISORY_TIMEOUT_MS: z.coerce.number().int().positive().default(2000),

  /**
   * Per-RPC deadline for `AnalyzeDlp` (its own **dlp lane**). manar-ai classifies DLP with an LLM
   * whenever a provider is configured, which routinely takes longer than the hot lane's 2 s, so
   * DLP gets its own deadline and its own breaker: slow classifications never open the hot
   * lane's breaker for risk and prompt-injection signals. Shares the hot lane's threshold and
   * cooldown values.
   */
  AI_ADVISORY_DLP_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(10_000),

  /**
   * Consecutive-failure threshold (timeout, transport error, or gRPC
   * status != OK) for the **hot lane** only, before `AiAdvisoryClient`'s
   * hot-lane circuit breaker opens and starts skipping hot-lane calls
   * entirely for `AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS` — see that
   * class's doc comment for the full state machine and why the long-form
   * lane has its own, independent breaker (`AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD`).
   */
  AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: z.coerce
    .number()
    .int()
    .positive()
    .default(3),

  /** How long the **hot lane**'s circuit stays open (skipping calls, returning null immediately) before the next hot-lane call is allowed through as a trial. */
  AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(30_000),

  /**
   * Per-RPC deadline in milliseconds for the **long-form lane**
   * (`SummarizeIncident`/`SuggestPolicy`/`InvestigateAudit` — explicit,
   * user-initiated, off the authorization path; nothing blocks on them).
   * These invoke a real LLM generation and routinely take several seconds,
   * so this is deliberately much longer than `AI_ADVISORY_TIMEOUT_MS` — see
   * `AiAdvisoryClient`'s doc comment for why this lane must never share the
   * hot lane's short deadline.
   */
  AI_ADVISORY_LONGFORM_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .positive()
    // Above manar-ai's own 30 s provider timeout, so its structured "provider timed out" answer
    // arrives instead of a deadline error that counts against the breaker.
    .default(40_000),

  /**
   * Consecutive-failure threshold for the **long-form lane** only, before
   * `AiAdvisoryClient`'s long-form circuit breaker opens — independent of
   * the hot lane's breaker above, so a run of slow/failed generations never
   * suppresses inline risk/DLP/prompt-injection signals. See that class's
   * doc comment.
   */
  AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD: z.coerce
    .number()
    .int()
    .positive()
    .default(3),

  /** How long the **long-form lane**'s circuit stays open before the next long-form call is allowed through as a trial — independent of the hot lane's cooldown above. */
  AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(30_000),

  /**
   * Phase 12a (Section 54, data residency enforcement): which AI provider
   * `manar-ai` is *currently configured* to use for this deployment.
   * `manar-api` has no way to introspect `manar-ai`'s own `AI_PROVIDER`
   * setting over the gRPC `AnalysisService` contract (there is no
   * "describe yourself" RPC) — this is this side's own declaration of the
   * same fact, which an operator must keep in sync with whatever
   * `manar-ai`'s compose/deployment config actually sets. Only `anthropic`
   * is "external" for the purpose of `AiAdvisoryClient`'s
   * `allowExternalAi` gate below — `ollama`/`vllm` are self-hosted model
   * backends, so a tenant's `allowExternalAi = false` never blocks calls
   * against them (see docs/ai-security-model.md's "Data residency
   * enforcement" section and `isExternalAiProvider` below). Defaults to
   * `ollama`, matching `deploy/docker-compose.yml`'s own `manar-ai`
   * service configuration (`docs/ai-security-model.md`'s "Local infra"
   * section).
   */
  AI_ADVISORY_PROVIDER: z
    .enum(['anthropic', 'ollama', 'vllm'])
    .default('ollama'),

  /**
   * Gate 0 R5: a tool result the prompt-injection advisory flags with at
   * least this confidence (0-1) is withheld from the agent
   * (`CredentialBrokerService.applyPostCallAdvisories`). Below it the
   * result is still returned and only the agent's risk flag is set. An
   * unavailable advisory never withholds anything.
   */
  PROMPT_INJECTION_BLOCK_THRESHOLD: z.coerce
    .number()
    .min(0)
    .max(1)
    .default(0.8),
});

/** The only provider this codebase currently treats as "external" (leaves this deployment's infrastructure) — see `AI_ADVISORY_PROVIDER`'s own doc comment. */
export function isExternalAiProvider(
  provider: AiAdvisoryConfig['AI_ADVISORY_PROVIDER'],
): boolean {
  return provider === 'anthropic';
}

export type AiAdvisoryConfig = z.infer<typeof AiAdvisoryConfigSchema>;

/**
 * Whether mTLS to manar-ai is switched on.
 *
 * The flag is a `'true' | 'false'` string rather than a coerced boolean on
 * purpose: `z.coerce.boolean()` runs JavaScript's `Boolean(...)`, under
 * which the string `"false"` is **true**. A security control that silently
 * inverts when someone writes the obvious thing in a `.env` file is worse
 * than no control.
 */
export function aiAdvisoryTlsEnabled(config: {
  AI_ADVISORY_TLS_ENABLED: 'true' | 'false';
}): boolean {
  return config.AI_ADVISORY_TLS_ENABLED === 'true';
}

/**
 * Startup validation for the mTLS material. Deliberately all-or-nothing.
 *
 * A half-configured mTLS client is the worst of the three possible states:
 * it looks configured, and it fails at connect time as a generic "AI
 * advisory unavailable" — which the circuit breaker then reports as a
 * degraded dependency. That is the correct fail-secure *behaviour* and a
 * useless *diagnostic*. Failing at startup with the missing variable named
 * is what an operator can act on.
 *
 * Lives here rather than as a `.superRefine` on the schema because
 * `AppConfigSchema` composes these with `.extend(Schema.shape)`, and
 * `.shape` exists only on a plain `ZodObject` — a refinement would silently
 * break that composition.
 */
export function assertAiAdvisoryTlsMaterial(config: {
  AI_ADVISORY_TLS_ENABLED: 'true' | 'false';
  AI_ADVISORY_TLS_CA_FILE?: string;
  AI_ADVISORY_TLS_CERT_FILE?: string;
  AI_ADVISORY_TLS_KEY_FILE?: string;
}): void {
  if (!aiAdvisoryTlsEnabled(config)) return;

  const missing = (
    [
      'AI_ADVISORY_TLS_CA_FILE',
      'AI_ADVISORY_TLS_CERT_FILE',
      'AI_ADVISORY_TLS_KEY_FILE',
    ] as const
  ).filter((key) => config[key] === undefined || config[key] === '');

  if (missing.length > 0) {
    throw new Error(
      `AI_ADVISORY_TLS_ENABLED is true but ${missing.join(', ')} ${
        missing.length === 1 ? 'is' : 'are'
      } not set. mTLS to manar-ai needs the CA bundle, this service's client certificate and its key together — see AI_ADVISORY_TLS_ENABLED's doc comment for the certificate identity manar-ai requires.`,
    );
  }
}
