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

/**
 * The only code that talks to a model provider (ADR-0002). OpenAI-compatible
 * `/chat/completions`, non-streaming. Ollama first, Azure OpenAI second, Core42 Compass third
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
}
