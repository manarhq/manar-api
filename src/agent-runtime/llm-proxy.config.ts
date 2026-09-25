import { z } from 'zod';

/**
 * LLM proxy (ADR-0002). The agent never sees any of this: it calls
 * `POST /agent/v1/llm/chat/completions` and manar-api picks the upstream.
 * The Azure key is read from the environment only and never logged,
 * audited or returned.
 */
export const LlmProxyConfigSchema = z.object({
  /** `ollama` (local, the sovereignty path) or `azure_openai` (the pilot's customer deployment). */
  LLM_PROVIDER: z.enum(['ollama', 'azure_openai']).default('ollama'),
  /** OpenAI-compatible base URL of Ollama, `/chat/completions` is appended. */
  LLM_OLLAMA_BASE_URL: z.string().url().default('http://localhost:11434/v1'),
  /** Model sent upstream for `ollama`; the agent's own `model` field is ignored. */
  LLM_MODEL: z.string().min(1).default('qwen3.5:9b'),
  /** e.g. `https://<resource>.openai.azure.com` */
  LLM_AZURE_OPENAI_ENDPOINT: z.string().url().optional(),
  LLM_AZURE_OPENAI_DEPLOYMENT: z.string().min(1).optional(),
  LLM_AZURE_OPENAI_API_VERSION: z.string().min(1).default('2024-10-21'),
  AZURE_OPENAI_API_KEY: z.string().min(1).optional(),
  /** Per-task budget of upstream-reported total tokens (prompt + completion). */
  LLM_TASK_TOKEN_BUDGET: z.coerce.number().int().positive().default(200_000),
  /** A 9B model on a consumer GPU can take a minute or more for a long prompt. */
  LLM_UPSTREAM_TIMEOUT_MS: z.coerce.number().int().positive().default(180_000),
});

export type LlmProxyConfig = z.infer<typeof LlmProxyConfigSchema>;
