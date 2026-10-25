import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { LlmProvider } from '../platform/catalog.validation';

export interface UpstreamChatRequest {
  messages: unknown[];
  tools?: unknown[];
  tool_choice?: unknown;
  temperature?: number;
  max_tokens?: number;
  /** Passed through; the console assistant sets `none` for Ollama. */
  reasoning_effort?: 'none' | 'minimal' | 'low' | 'medium' | 'high';
}

export interface UpstreamChatResponse {
  /** The upstream's OpenAI-shaped JSON body, passed back to the agent as is. */
  body: Record<string, unknown> & {
    model?: string;
    usage?: {
      prompt_tokens?: number;
      completion_tokens?: number;
      total_tokens?: number;
    };
  };
  provider: LlmProvider;
  model: string;
}

/** A tenant's model from its catalog (src/platform/catalog.*); absent = the deployment default. */
export interface LlmRouteOverride {
  provider: LlmProvider;
  model: string;
}

/** Upstream-reported total tokens, else prompt + completion, else a length/4 estimate (never 0). */
export function chargedTokens(
  response: UpstreamChatResponse,
  sent: unknown,
): number {
  const usage = response.body.usage ?? {};
  return (
    usage.total_tokens ??
    ((usage.prompt_tokens ?? 0) + (usage.completion_tokens ?? 0) ||
      Math.ceil(
        (JSON.stringify(sent).length +
          JSON.stringify(response.body.choices ?? '').length) /
          4,
      ))
  );
}

/** The upstream could not answer (unreachable, timeout, non-2xx, not JSON). Never carries the upstream body. */
export class LlmUpstreamError extends Error {
  constructor(readonly detail: string) {
    super(`LLM upstream failed: ${detail}`);
    this.name = 'LlmUpstreamError';
  }
}

export type AnthropicProvider =
  'anthropic' | 'azure_foundry' | 'openai_translate' | 'none';

/** An Anthropic-format error body (`{type: "error", error: {type, message}}`). */
export interface AnthropicErrorBody {
  type: 'error';
  error: { type: string; message: string };
}

/**
 * The Anthropic-format upstream refused the request itself (400, 404, 413, 422): the client
 * needs its error to adjust (Claude Code retries without a capability the upstream rejects).
 * Carries only the error's type and message.
 */
export class LlmUpstreamRejected extends Error {
  constructor(
    readonly status: number,
    readonly body: AnthropicErrorBody,
  ) {
    super(`LLM upstream rejected the request: HTTP ${status}`);
    this.name = 'LlmUpstreamRejected';
  }
}

/** Statuses whose Anthropic error body goes back to the client; any other non-2xx is a 502. */
const PASSED_REJECTIONS = new Set([400, 404, 413, 422]);

/**
 * The only code that talks to a model provider (ADR-0002). OpenAI-compatible
 * `/chat/completions`, non-streaming; and the Anthropic-format upstream (`anthropicMessages`,
 * Anthropic or Microsoft Foundry, JSON or SSE). Ollama first, Azure OpenAI second, Core42 Compass third
 * (OpenAI-compatible, bearer key; not yet run against a live Compass endpoint). Keys go in one
 * header each and nowhere else. A tenant's catalog may pick the provider and model; a provider
 * the deployment has no endpoint or key for refuses the call.
 *
 * ponytail: one endpoint and key per provider per deployment. Per-tenant endpoints and keys
 * (two Azure customers on one hosted deployment) belong in OpenBao when that happens.
 */
@Injectable()
export class LlmUpstreamClient {
  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  async chat(
    request: UpstreamChatRequest,
    route?: LlmRouteOverride | null,
  ): Promise<UpstreamChatResponse> {
    const provider: LlmProvider =
      route?.provider ??
      this.config.get('LLM_PROVIDER', { infer: true }) ??
      'ollama';
    const timeoutMs = this.config.get('LLM_UPSTREAM_TIMEOUT_MS', {
      infer: true,
    });
    let url: string;
    let model: string;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (provider === 'azure_openai') {
      const endpoint = this.config.get('LLM_AZURE_OPENAI_ENDPOINT', {
        infer: true,
      });
      const deployment = this.config.get('LLM_AZURE_OPENAI_DEPLOYMENT', {
        infer: true,
      });
      const key = this.config.get('AZURE_OPENAI_API_KEY', { infer: true });
      if (!endpoint || !deployment || !key) {
        throw new LlmUpstreamError('azure_openai is not configured');
      }
      const apiVersion = this.config.get('LLM_AZURE_OPENAI_API_VERSION', {
        infer: true,
      });
      model = route?.model ?? deployment;
      url = `${endpoint.replace(/\/+$/, '')}/openai/deployments/${encodeURIComponent(model)}/chat/completions?api-version=${encodeURIComponent(apiVersion)}`;
      headers['api-key'] = key;
      // gpt-5-mini's lowest setting is `minimal`; it rejects `none`.
      if (request.reasoning_effort === 'none') {
        request = { ...request, reasoning_effort: 'minimal' };
      }
    } else if (provider === 'core42_compass') {
      const base = this.config.get('LLM_CORE42_BASE_URL', { infer: true });
      const key = this.config.get('CORE42_API_KEY', { infer: true });
      if (!base || !key || !route?.model) {
        throw new LlmUpstreamError('core42_compass is not configured');
      }
      url = `${base.replace(/\/+$/, '')}/chat/completions`;
      model = route.model;
      headers.Authorization = `Bearer ${key}`;
    } else {
      url = `${this.config.get('LLM_OLLAMA_BASE_URL', { infer: true }).replace(/\/+$/, '')}/chat/completions`;
      model = route?.model ?? this.config.get('LLM_MODEL', { infer: true });
    }

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ ...request, model, stream: false }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw new LlmUpstreamError(
        error instanceof Error ? error.name : 'request failed',
      );
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new LlmUpstreamError(`HTTP ${response.status}`);
    }
    let body: UpstreamChatResponse['body'];
    try {
      body = (await response.json()) as UpstreamChatResponse['body'];
    } catch {
      throw new LlmUpstreamError('invalid JSON');
    }
    if (!body || typeof body !== 'object' || !Array.isArray(body.choices)) {
      throw new LlmUpstreamError('not a chat completion');
    }
    return { body, provider, model };
  }

  /** The Anthropic-format upstream actually usable: a provider without its key or endpoint is `none`. */
  anthropicProvider(): AnthropicProvider {
    const provider = this.config.get('LLM_ANTHROPIC_PROVIDER', { infer: true });
    if (provider === 'anthropic' && !this.anthropicTarget('anthropic'))
      return 'none';
    if (provider === 'azure_foundry' && !this.anthropicTarget('azure_foundry'))
      return 'none';
    return provider;
  }

  private anthropicTarget(
    provider: 'anthropic' | 'azure_foundry',
  ): { base: string; key: string } | null {
    const base =
      provider === 'anthropic'
        ? this.config.get('LLM_ANTHROPIC_BASE_URL', { infer: true })
        : this.config.get('LLM_AZURE_FOUNDRY_ENDPOINT', { infer: true });
    const key =
      provider === 'anthropic'
        ? this.config.get('ANTHROPIC_API_KEY', { infer: true })
        : this.config.get('AZURE_FOUNDRY_API_KEY', { infer: true });
    return base && key ? { base: base.replace(/\/+$/, ''), key } : null;
  }

  /**
   * `POST <base>/v1/messages` on the Anthropic or Microsoft Foundry upstream (both take the key
   * as `x-api-key`). Only `anthropic-version` and `anthropic-beta` come from the client; its own
   * credentials never leave manar-api. Returns the 2xx response with its body unread (JSON or
   * SSE); `signal` bounds the whole exchange.
   */
  async anthropicMessages(
    body: Record<string, unknown>,
    client: { version?: string; beta?: string },
    signal: AbortSignal,
  ): Promise<{ response: Response; provider: AnthropicProvider }> {
    const provider = this.anthropicProvider();
    const target =
      provider === 'anthropic' || provider === 'azure_foundry'
        ? this.anthropicTarget(provider)
        : null;
    if (!target)
      throw new LlmUpstreamError(`${provider} is not an Anthropic upstream`);
    let response: Response;
    try {
      response = await fetch(`${target.base}/v1/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': target.key,
          'anthropic-version': client.version ?? '2023-06-01',
          ...(client.beta ? { 'anthropic-beta': client.beta } : {}),
        },
        body: JSON.stringify(body),
        signal,
      });
    } catch (error) {
      throw new LlmUpstreamError(
        error instanceof Error ? error.name : 'request failed',
      );
    }
    if (response.ok) return { response, provider };
    const rejection = PASSED_REJECTIONS.has(response.status)
      ? ((await response.json().catch(() => null)) as unknown)
      : await response.body?.cancel().catch(() => null);
    const error = (rejection as Partial<AnthropicErrorBody> | null)?.error;
    if (typeof error?.type === 'string' && typeof error.message === 'string') {
      throw new LlmUpstreamRejected(response.status, {
        type: 'error',
        error: { type: error.type, message: error.message },
      });
    }
    throw new LlmUpstreamError(`HTTP ${response.status}`);
  }
}
