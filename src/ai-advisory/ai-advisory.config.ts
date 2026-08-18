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
});

export type AiAdvisoryConfig = z.infer<typeof AiAdvisoryConfigSchema>;
