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
   * Per-RPC deadline in milliseconds, applied to every `AnalyzeRisk`/
   * `AnalyzePromptInjection`/`AnalyzeDlp` call. Short and on the hot
   * authorization/tool-invocation path (Section 80: an AI outage must add
   * no more than this configured amount of latency, never hang the
   * pipeline waiting on a slow/unreachable model backend) — see
   * `AiAdvisoryClient`'s doc comment for why 2s is the chosen default.
   */
  AI_ADVISORY_TIMEOUT_MS: z.coerce.number().int().positive().default(2000),

  /**
   * Consecutive-failure threshold (timeout, transport error, or gRPC
   * status != OK) before `AiAdvisoryClient`'s circuit breaker opens and
   * starts skipping calls entirely for `AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS`
   * — see that class's doc comment for the full state machine.
   */
  AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: z.coerce
    .number()
    .int()
    .positive()
    .default(3),

  /** How long the circuit stays open (skipping calls, returning null immediately) before the next call is allowed through as a trial. */
  AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: z.coerce
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
});

/** The only provider this codebase currently treats as "external" (leaves this deployment's infrastructure) — see `AI_ADVISORY_PROVIDER`'s own doc comment. */
export function isExternalAiProvider(
  provider: AiAdvisoryConfig['AI_ADVISORY_PROVIDER'],
): boolean {
  return provider === 'anthropic';
}

export type AiAdvisoryConfig = z.infer<typeof AiAdvisoryConfigSchema>;
