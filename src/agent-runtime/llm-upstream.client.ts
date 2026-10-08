import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';

export interface UpstreamChatRequest {
  messages: unknown[];
  tools?: unknown[];
  tool_choice?: unknown;
  temperature?: number;
  max_tokens?: number;
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
  provider: 'ollama' | 'azure_openai';
  model: string;
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
 * `/chat/completions`, non-streaming. Ollama first, Azure OpenAI second;
 * the Azure key goes in the `api-key` header and nowhere else.
 */
@Injectable()
export class LlmUpstreamClient {
  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  async chat(request: UpstreamChatRequest): Promise<UpstreamChatResponse> {
    const provider = this.config.get('LLM_PROVIDER', { infer: true });
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
      url = `${endpoint.replace(/\/+$/, '')}/openai/deployments/${encodeURIComponent(deployment)}/chat/completions?api-version=${encodeURIComponent(apiVersion)}`;
      model = deployment;
      headers['api-key'] = key;
      // gpt-5-mini's lowest setting is `minimal`; it rejects `none`.
      if (request.reasoning_effort === 'none') {
        request = { ...request, reasoning_effort: 'minimal' };
      }
    } else {
      url = `${this.config.get('LLM_OLLAMA_BASE_URL', { infer: true }).replace(/\/+$/, '')}/chat/completions`;
      model = this.config.get('LLM_MODEL', { infer: true });
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
