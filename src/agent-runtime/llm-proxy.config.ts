import { z } from 'zod';

/** A chart renders an absent optional secret as an empty string; treat it as unset. */
const optionalSecret = z.preprocess(
  (v) => (v === '' ? undefined : v),
  z.string().min(1).optional(),
);

function httpsOrLoopback(v: string): boolean {
  const url = new URL(v);
  return (
    url.protocol === 'https:' ||
    ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
  );
}

/**
 * LLM proxy (ADR-0002). The agent never sees any of this: it calls
 * `POST /agent/v1/llm/chat/completions` and manar-api picks the upstream.
 * The Azure key is read from the environment only and never logged,
 * audited or returned.
 */
export const LlmProxyConfigSchema = z.object({
  /** `ollama` (local, the sovereignty path) or `azure_openai` (the pilot's customer deployment). */
  LLM_PROVIDER: z.enum(['ollama', 'azure_openai']).default('ollama'),
  /**
   * Whether the deployment's default model (LLM_PROVIDER) runs in the UAE. Ollama runs inside the
   * deployment and follows its residency; set this for an Azure OpenAI deployment in UAE North.
   * The tenant residency rule (src/platform/catalog.*) applies to the default model too.
   */
  LLM_DEFAULT_UAE_RESIDENT: z.enum(['true', 'false']).default('false'),
  /** Core42 Compass, OpenAI-compatible base URL (`/chat/completions` is appended). Used only by a tenant whose catalog picks it. */
  LLM_CORE42_BASE_URL: z
    .string()
    .url()
    .refine((v) => v.startsWith('https://'), 'must be https')
    .optional(),
  CORE42_API_KEY: z.string().min(1).optional(),
  /** OpenAI-compatible base URL of Ollama, `/chat/completions` is appended. */
  LLM_OLLAMA_BASE_URL: z.string().url().default('http://localhost:11434/v1'),
  /** Model sent upstream for `ollama`; the agent's own `model` field is ignored. */
  LLM_MODEL: z.string().min(1).default('qwen3.5:9b'),
  /** e.g. `https://<resource>.openai.azure.com` */
  LLM_AZURE_OPENAI_ENDPOINT: z.string().url().optional(),
  LLM_AZURE_OPENAI_DEPLOYMENT: z.string().min(1).optional(),
  LLM_AZURE_OPENAI_API_VERSION: z.string().min(1).default('2024-10-21'),
  AZURE_OPENAI_API_KEY: z.string().min(1).optional(),
  /**
   * Upstream of `POST /agent/v1/llm/anthropic/v1/messages` (Anthropic Messages format, for
   * Claude Code and other Anthropic clients). `anthropic` and `azure_foundry` without their key
   * (or endpoint) behave as `none`: 404 `anthropic_disabled`. `openai_translate` converts to the
   * OpenAI-format upstream above (LLM_PROVIDER or the tenant's catalog model) and back.
   */
  LLM_ANTHROPIC_PROVIDER: z
    .enum(['anthropic', 'azure_foundry', 'openai_translate', 'none'])
    .default('anthropic'),
  /** `/v1/messages` is appended. https, or http on loopback only (tests, a local relay). */
  LLM_ANTHROPIC_BASE_URL: z
    .string()
    .url()
    .refine(httpsOrLoopback, 'must be https (http only on loopback)')
    .default('https://api.anthropic.com'),
  /** OpenBao `kv/prod/llm-anthropic` property `api_key`. Empty counts as unset. */
  ANTHROPIC_API_KEY: optionalSecret,
  /** Microsoft Foundry: `https://<resource>.services.ai.azure.com/anthropic` (`/v1/messages` is appended). */
  LLM_AZURE_FOUNDRY_ENDPOINT: z
    .string()
    .url()
    .refine(httpsOrLoopback, 'must be https (http only on loopback)')
    .optional(),
  AZURE_FOUNDRY_API_KEY: optionalSecret,
  /**
   * Comma-separated model ids (Foundry: deployment names) this install serves in Anthropic
   * format. A request naming another model is refused (400 `llm_model_not_served`). Empty: the
   * Anthropic-format endpoint is off (404 `anthropic_disabled`). Listed by `GET /agent/v1/llm/models`.
   */
  LLM_ANTHROPIC_MODELS: z.string().default(''),
  /**
   * `anthropic-beta` values forwarded upstream (comma-separated); others are dropped. Default:
   * the values Claude Code sends that pair with features this proxy passes on (interleaved
   * thinking, context management, effort, 1M context, fine-grained tool streaming).
   */
  LLM_ANTHROPIC_BETAS: z
    .string()
    .default(
      'interleaved-thinking-2025-05-14,context-management-2025-06-27,effort-2025-11-24,context-1m-2025-08-07,fine-grained-tool-streaming-2025-05-14',
    ),
  /**
   * Response DLP on a streamed Anthropic-format answer. `buffer` (default): the whole answer is
   * read, checked once, then replayed as events. `incremental`: events are checked and released
   * as they arrive, held back only as far as a credential or PII match could still be growing;
   * the first tokens arrive sooner, but the check is weaker (ADR-0002 A2).
   */
  LLM_ANTHROPIC_STREAM_DLP: z.enum(['buffer', 'incremental']).default('buffer'),
  /** A streamed Anthropic-format response is cut after this long, idle or not. */
  LLM_STREAM_MAX_MS: z.coerce.number().int().positive().default(900_000),
  /** Whether the `anthropic`/`azure_foundry` upstream processes prompts in the UAE (tenant residency rule). */
  LLM_ANTHROPIC_UAE_RESIDENT: z.enum(['true', 'false']).default('false'),
  /** Per-task budget of upstream-reported total tokens (prompt + completion). */
  LLM_TASK_TOKEN_BUDGET: z.coerce.number().int().positive().default(200_000),
  /** A 9B model on a consumer GPU can take a minute or more for a long prompt. */
  LLM_UPSTREAM_TIMEOUT_MS: z.coerce.number().int().positive().default(180_000),
});

export type LlmProxyConfig = z.infer<typeof LlmProxyConfigSchema>;
