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

/**
 * Azure OpenAI serves GPT-5 reasoning models, which reject `max_tokens` (use
 * `max_completion_tokens`) and any `temperature`. The original GPT-5 deployments (gpt-5,
 * gpt-5-mini, gpt-5-nano) take `minimal` but not `none`; gpt-5.1 and later take `none` but not
 * `minimal`.
 *
 * ponytail: the GPT-5 generation is read from the deployment name (Azure's default, the model
 * name). A deployment named otherwise passes `reasoning_effort` through unchanged.
 */
export function forAzureReasoningModel(
  request: UpstreamChatRequest,
  deployment: string,
): UpstreamChatRequest & { max_completion_tokens?: number } {
  const { max_tokens, ...rest } = request;
  delete rest.temperature;
  const out: UpstreamChatRequest & { max_completion_tokens?: number } = {
    ...rest,
    ...(max_tokens !== undefined ? { max_completion_tokens: max_tokens } : {}),
  };
  if (out.reasoning_effort === 'none' && /^gpt-5(-|$)/.test(deployment)) {
    out.reasoning_effort = 'minimal';
  } else if (
    out.reasoning_effort === 'minimal' &&
    /^gpt-5\.\d/.test(deployment)
  ) {
    out.reasoning_effort = 'none';
  }
  return out;
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

  /** Where a request goes: the provider's URL, headers and model, and the request shaped for it. */
  private resolve(
    request: UpstreamChatRequest,
    route?: LlmRouteOverride | null,
  ): {
    provider: LlmProvider;
    url: string;
    model: string;
    headers: Record<string, string>;
    request: UpstreamChatRequest;
  } {
    const provider: LlmProvider =
      route?.provider ??
      this.config.get('LLM_PROVIDER', { infer: true }) ??
      'ollama';
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
      request = forAzureReasoningModel(request, model);
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
    return { provider, url, model, headers, request };
  }

  async chat(
    request: UpstreamChatRequest,
    route?: LlmRouteOverride | null,
    /** Aborts the call (the client went away); the timeout applies either way. */
    signal?: AbortSignal,
    /** Per-call timeout; the deployment's `LLM_UPSTREAM_TIMEOUT_MS` when absent. */
    timeoutOverrideMs?: number,
  ): Promise<UpstreamChatResponse> {
    const {
      provider,
      url,
      model,
      headers,
      request: shaped,
    } = this.resolve(request, route);
    const configuredMs = this.config.get('LLM_UPSTREAM_TIMEOUT_MS', {
      infer: true,
    });
    const timeoutMs = timeoutOverrideMs ?? configuredMs;

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ ...shaped, model, stream: false }),
        signal: signal
          ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
          : AbortSignal.timeout(timeoutMs),
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

  /**
   * Streaming `chat`: the same request with `stream: true`. `onContent` gets each piece of the
   * answer text as it arrives; the return value is the assembled response, shaped like `chat`'s
   * (message with content and tool calls, usage, model) so callers treat both alike.
   *
   * Bounded three ways: `firstTokenMs` to the first byte, `idleMs` of silence between chunks, and
   * `totalMs` overall. `signal` is the client going away.
   */
  async chatStream(
    request: UpstreamChatRequest,
    route: LlmRouteOverride | null | undefined,
    onContent: (text: string) => void,
    limits: {
      signal?: AbortSignal;
      firstTokenMs: number;
      idleMs: number;
      totalMs: number;
    },
  ): Promise<UpstreamChatResponse> {
    const {
      provider,
      url,
      model,
      headers,
      request: shaped,
    } = this.resolve(request, route);
    const ctl = new AbortController();
    const total = setTimeout(() => ctl.abort(), limits.totalMs);
    let wait = setTimeout(() => ctl.abort(), limits.firstTokenMs);
    const touch = (): void => {
      clearTimeout(wait);
      wait = setTimeout(() => ctl.abort(), limits.idleMs);
    };
    const onClientGone = (): void => ctl.abort();
    limits.signal?.addEventListener('abort', onClientGone, { once: true });
    if (limits.signal?.aborted) ctl.abort();
    try {
      let response: Response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: { ...headers, Accept: 'text/event-stream' },
          body: JSON.stringify({
            ...shaped,
            model,
            stream: true,
            stream_options: { include_usage: true },
          }),
          signal: ctl.signal,
        });
      } catch (error) {
        throw new LlmUpstreamError(
          error instanceof Error ? error.name : 'request failed',
        );
      }
      if (!response.ok || !response.body) {
        await response.body?.cancel().catch(() => undefined);
        throw new LlmUpstreamError(`HTTP ${response.status}`);
      }
      touch();
      const acc = new StreamAccumulator(model);
      try {
        const decoder = new TextDecoder();
        let pending = '';
        for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
          touch();
          pending += decoder.decode(chunk, { stream: true });
          let nl: number;
          while ((nl = pending.indexOf('\n')) !== -1) {
            const line = pending.slice(0, nl).trimEnd();
            pending = pending.slice(nl + 1);
            if (!line.startsWith('data:')) continue;
            const data = line.slice(5).trim();
            if (data === '[DONE]') continue;
            const text = acc.add(data);
            if (text) onContent(text);
          }
        }
      } catch (error) {
        if (error instanceof LlmUpstreamError) throw error;
        throw new LlmUpstreamError(
          error instanceof Error ? error.name : 'stream failed',
        );
      }
      return { body: acc.body(), provider, model };
    } finally {
      clearTimeout(total);
      clearTimeout(wait);
      limits.signal?.removeEventListener('abort', onClientGone);
    }
  }

  /** Model ids served in Anthropic format (`LLM_ANTHROPIC_MODELS`). */
  anthropicModels(): string[] {
    return this.config
      .get('LLM_ANTHROPIC_MODELS', { infer: true })
      .split(',')
      .map((m) => m.trim())
      .filter(Boolean);
  }

  /**
   * The Anthropic-format upstream actually usable: `none` without a model list, and for a
   * provider without its key or endpoint.
   */
  anthropicProvider(): AnthropicProvider {
    if (this.anthropicModels().length === 0) return 'none';
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

/** Builds the non-streaming response shape from OpenAI-style `chat.completion.chunk` events. */
class StreamAccumulator {
  private content = '';
  private model: string;
  private usage: UpstreamChatResponse['body']['usage'];
  private readonly calls: { id: string; name: string; args: string }[] = [];

  constructor(model: string) {
    this.model = model;
  }

  /** Adds one event's JSON; returns the answer text it carried, if any. */
  add(json: string): string {
    let chunk: {
      model?: string;
      usage?: UpstreamChatResponse['body']['usage'] | null;
      choices?: {
        delta?: {
          content?: string | null;
          tool_calls?: {
            index?: number;
            id?: string;
            function?: { name?: string; arguments?: string };
          }[];
        };
      }[];
    };
    try {
      chunk = JSON.parse(json) as typeof chunk;
    } catch {
      throw new LlmUpstreamError('invalid stream event');
    }
    if (chunk.model) this.model = chunk.model;
    if (chunk.usage) this.usage = chunk.usage;
    const delta = chunk.choices?.[0]?.delta;
    for (const call of delta?.tool_calls ?? []) {
      const at = call.index ?? 0;
      const slot = (this.calls[at] ??= { id: '', name: '', args: '' });
      if (call.id) slot.id = call.id;
      if (call.function?.name) slot.name += call.function.name;
      if (call.function?.arguments) slot.args += call.function.arguments;
    }
    const text = delta?.content ?? '';
    this.content += text;
    return text;
  }

  body(): UpstreamChatResponse['body'] {
    const toolCalls = this.calls
      .filter((c) => c.name)
      .map((c) => ({
        id: c.id,
        type: 'function',
        function: { name: c.name, arguments: c.args },
      }));
    return {
      model: this.model,
      ...(this.usage ? { usage: this.usage } : {}),
      choices: [
        {
          message: {
            role: 'assistant',
            content: this.content,
            ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
          },
        },
      ],
    };
  }
}
