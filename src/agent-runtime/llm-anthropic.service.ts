import { setTimeout as sleep } from 'node:timers/promises';
import {
  BadGatewayException,
  HttpException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { AgentContext } from '../agent-mtls/agent-context';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { failClosed } from '../common/fail-closed/fail-closed';
import { CatalogService } from '../platform/catalog.service';
import { denied } from './agent-task-access.service';
import {
  AnthropicMessagesRequestSchema,
  AnthropicStreamGuard,
  DlpBlocked,
  errorEvent,
  fromOpenAiChat,
  holdOpaque,
  messageEvents,
  parseSse,
  PING,
  requestRefusal,
  scanMessage,
  sse,
  toOpenAiChat,
  usageTokens,
  type AnthropicUsage,
} from './llm-anthropic';
import {
  LlmProxyService,
  sha256,
  upstreamFailure,
  type AdmittedCall,
  type CallRecord,
} from './llm-proxy.service';
import {
  LlmUpstreamClient,
  LlmUpstreamError,
  LlmUpstreamRejected,
} from './llm-upstream.client';

type Json = Record<string, unknown>;
type Call = AdmittedCall<unknown>;

export type AnthropicReply =
  { json: Json } | { stream: AsyncGenerator<string> };

/** While a synthesized stream waits for its upstream, a ping this often keeps the client from timing out. */
const PING_MS = 10_000;
const EVENT_END = /\r?\n\r?\n/;

/**
 * `POST /agent/v1/llm/anthropic/v1/messages` (manar-edge design section 6): the Anthropic
 * Messages format for Claude Code and other Anthropic clients, through the same gates as chat
 * completions (`LlmProxyService.admit`: task access, catalog with this upstream's own residency,
 * token budget, DLP on system, messages, tool results and tools), then the upstream chosen by
 * `LLM_ANTHROPIC_PROVIDER`, then response DLP (floor) before anything reaches the agent, budget
 * from the reported usage (cache tokens included) and the `llm.request` audit.
 *
 * Streaming is passed through event by event (`AnthropicStreamGuard`); the final
 * `message_delta`/`message_stop` go out only after the call is charged and audited, and a
 * credential in the output ends the stream with an Anthropic `error` event.
 */
@Injectable()
export class LlmAnthropicService {
  constructor(
    private readonly proxy: LlmProxyService,
    private readonly upstream: LlmUpstreamClient,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly catalog: CatalogService,
  ) {}

  async messages(
    agent: AgentContext,
    taskId: string,
    rawBody: unknown,
    client: { version?: string; beta?: string },
    signal: AbortSignal,
  ): Promise<AnthropicReply> {
    const provider = this.upstream.anthropicProvider();
    if (provider === 'none') {
      throw new NotFoundException({ reason: 'anthropic_disabled' });
    }
    const request = parseBodyOrThrow(AnthropicMessagesRequestSchema, rawBody);
    const started = Date.now();
    const stream = request.stream === true;
    const record: CallRecord = {
      taskId,
      outcome: 'DENIED',
      format: 'anthropic',
      stream,
      latencyMs: 0,
      messageCount: request.messages.length,
      toolCount: request.tools?.length ?? 0,
      promptSha256: sha256({
        system: request.system,
        messages: request.messages,
      }),
    };

    try {
      const refusal = requestRefusal(request);
      if (refusal) throw refusal;
      const translate = provider === 'openai_translate';
      const { held, restore } = holdOpaque({
        system: request.system,
        messages: request.messages,
        tools: request.tools,
      });
      const call = await this.proxy.admit(
        agent,
        taskId,
        record,
        held,
        translate
          ? undefined
          : {
              external: true,
              uaeResident:
                this.config.get('LLM_ANTHROPIC_UAE_RESIDENT', {
                  infer: true,
                }) === 'true',
            },
      );
      const body = {
        ...request,
        ...restore(call.dlp.value),
        model: this.pickModel(request.model),
      };

      if (translate) {
        const chat = toOpenAiChat(body);
        const pending = this.upstream.chat(chat, call.route).then(
          (res) => {
            record.provider = res.provider;
            record.model = res.body.model ?? res.model;
            return fromOpenAiChat(res.body, record.model);
          },
          (error: unknown) => {
            throw upstreamFailure(record, error);
          },
        );
        if (!stream) {
          return {
            json: await this.deliver(
              agent,
              call,
              record,
              await pending,
              chat,
              started,
            ),
          };
        }
        pending.catch(() => undefined); // observed by the generator; never unhandled
        return {
          stream: this.synthesize(agent, call, record, pending, chat, started),
        };
      }

      record.provider = provider;
      record.model = body.model;
      const timeoutMs = this.config.get('LLM_UPSTREAM_TIMEOUT_MS', {
        infer: true,
      });
      if (!stream) {
        const message = await this.upstreamCall(record, async () => {
          const { response } = await this.upstream.anthropicMessages(
            body,
            client,
            AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
          );
          const json = (await response.json().catch(() => null)) as Json | null;
          if (json?.type !== 'message' || !Array.isArray(json.content)) {
            throw new LlmUpstreamError('not a message');
          }
          return json;
        });
        return {
          json: await this.deliver(agent, call, record, message, body, started),
        };
      }

      const idle = new IdleAbort(timeoutMs, signal);
      try {
        const { response } = await this.upstreamCall(record, () =>
          this.upstream.anthropicMessages(body, client, idle.signal),
        );
        return {
          stream: this.relay(
            agent,
            call,
            record,
            response,
            idle,
            signal,
            body,
            started,
          ),
        };
      } catch (error) {
        idle.clear();
        throw error;
      }
    } catch (error) {
      await this.proxy.recordRefusal(agent, record, error, started);
      throw error;
    }
  }

  /** `GET /agent/v1/llm/models`: the OpenAI-format model and the Anthropic-format models this install serves. */
  async models(agent: AgentContext): Promise<Json> {
    const catalog = await failClosed('catalog-store', () =>
      this.catalog.state(agent.tenant.id),
    );
    const openAi =
      catalog.model?.model ??
      (this.config.get('LLM_PROVIDER', { infer: true }) === 'azure_openai'
        ? this.config.get('LLM_AZURE_OPENAI_DEPLOYMENT', { infer: true })
        : this.config.get('LLM_MODEL', { infer: true }));
    const anthropic =
      this.upstream.anthropicProvider() === 'none'
        ? []
        : this.anthropicModels();
    const ids = [
      ...new Set([openAi, ...anthropic].filter((id): id is string => !!id)),
    ];
    // Both shapes at once: OpenAI's `object`/`created`/`owned_by` and Anthropic's
    // `type`/`created_at`/`display_name` (epoch: release date unknown).
    return {
      object: 'list',
      data: ids.map((id) => ({
        id,
        object: 'model',
        type: 'model',
        created: 0,
        created_at: '1970-01-01T00:00:00Z',
        display_name: id,
        owned_by: 'manar',
      })),
      has_more: false,
      first_id: ids[0] ?? null,
      last_id: ids.at(-1) ?? null,
    };
  }

  private anthropicModels(): string[] {
    return this.config
      .get('LLM_ANTHROPIC_MODELS', { infer: true })
      .split(',')
      .map((m) => m.trim())
      .filter(Boolean);
  }

  /** The client's model when this install serves it (or lists none), else the install's default. */
  private pickModel(requested: string): string {
    const models = this.anthropicModels();
    return models.length === 0 || models.includes(requested)
      ? requested
      : models[0]!;
  }

  /** Upstream failures as the client sees them: the upstream's own 4xx error, else 502. */
  private async upstreamCall<T>(
    record: CallRecord,
    fn: () => Promise<T>,
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof LlmUpstreamRejected) {
        record.outcome = 'UPSTREAM_ERROR';
        record.reason = `HTTP ${error.status}`;
        throw new HttpException(
          { ...error.body, reason: 'llm_upstream_rejected' },
          error.status,
        );
      }
      throw upstreamFailure(record, error);
    }
  }

  /** A whole message: response DLP, charge, audit, then the (redacted) message. */
  private async deliver(
    agent: AgentContext,
    call: Call,
    record: CallRecord,
    message: Json,
    sent: unknown,
    started: number,
  ): Promise<Json> {
    const scanned = scanMessage(message);
    record.responseDlp = {
      credentialTypes: scanned.credentialTypes,
      piiTypes: scanned.piiTypes,
    };
    const usage = (message.usage ?? {}) as AnthropicUsage;
    applyUsage(record, usage);
    await this.proxy.charge(
      agent,
      call,
      record,
      tokens(usage, sent, JSON.stringify(message.content).length),
    );
    if (scanned.credentialTypes.length) throw denied('dlp_policy_violation');
    await this.proxy.recordSuccess(agent, call.tenantClient, record, started);
    return scanned.message;
  }

  /** `openai_translate` with `stream: true`: pings while the upstream works, then the whole message as events. */
  private async *synthesize(
    agent: AgentContext,
    call: Call,
    record: CallRecord,
    pending: Promise<Json>,
    sent: unknown,
    started: number,
  ): AsyncGenerator<string> {
    try {
      let message: Json | undefined;
      while (!message) {
        message = await Promise.race([
          pending,
          sleep(PING_MS, undefined, { ref: false }),
        ]);
        if (!message) yield sse(PING);
      }
      const delivered = await this.deliver(
        agent,
        call,
        record,
        message,
        sent,
        started,
      );
      for (const e of messageEvents(delivered)) yield sse(e);
    } catch (error) {
      if (!(error instanceof HttpException)) throw error;
      await this.proxy.recordRefusal(agent, record, error, started);
      yield sse(errorEvent(error));
    }
  }

  /** `anthropic`/`azure_foundry` with `stream: true`: the upstream's events, through the guard, as they arrive. */
  private async *relay(
    agent: AgentContext,
    call: Call,
    record: CallRecord,
    response: Response,
    idle: IdleAbort,
    clientSignal: AbortSignal,
    sent: unknown,
    started: number,
  ): AsyncGenerator<string> {
    const guard = new AnthropicStreamGuard();
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let ended = false;
    // A cut stream still used tokens: count them (best effort) and record why it ended.
    const cut = async (outcome: CallRecord['outcome'], reason: string) => {
      ended = true;
      Object.assign(record, {
        outcome,
        reason,
        latencyMs: Date.now() - started,
      });
      applyUsage(record, guard.usage);
      record.responseDlp ??= {
        credentialTypes: [],
        piiTypes: [...guard.piiTypes].sort(),
      };
      await this.proxy
        .charge(
          agent,
          call,
          record,
          tokens(guard.usage, sent, guard.outputChars),
        )
        .catch(() => undefined);
      await this.proxy.recordFailure(agent, record);
    };

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done)
          throw new LlmUpstreamError('stream ended before message_stop');
        idle.touch();
        buffer += decoder.decode(value, { stream: true });
        for (let m = EVENT_END.exec(buffer); m; m = EVENT_END.exec(buffer)) {
          const event = parseSse(buffer.slice(0, m.index));
          buffer = buffer.slice(m.index + m[0].length);
          if (!event) continue;
          if (event.data.type === 'error') {
            const type = (event.data.error as Json | undefined)?.type;
            await cut('UPSTREAM_ERROR', `stream error: ${String(type)}`);
            yield sse({
              event: 'error',
              data: { ...event.data, reason: 'llm_upstream_unavailable' },
            });
            return;
          }
          for (const out of guard.push(event)) yield sse(out);
          if (event.data.type !== 'message_stop') continue;

          ended = true;
          applyUsage(record, guard.usage);
          record.responseDlp = {
            credentialTypes: [],
            piiTypes: [...guard.piiTypes].sort(),
          };
          try {
            await this.proxy.charge(
              agent,
              call,
              record,
              tokens(guard.usage, sent, guard.outputChars),
            );
            await this.proxy.recordSuccess(
              agent,
              call.tenantClient,
              record,
              started,
            );
          } catch (error) {
            await this.proxy.recordRefusal(agent, record, error, started);
            if (error instanceof HttpException) yield sse(errorEvent(error));
            return;
          }
          for (const e of guard.held) yield sse(e);
          return;
        }
      }
    } catch (error) {
      if (ended) throw error;
      if (error instanceof DlpBlocked) {
        record.responseDlp = {
          credentialTypes: error.types,
          piiTypes: [...guard.piiTypes].sort(),
        };
        await cut('DENIED', 'dlp_policy_violation');
        yield sse(errorEvent(denied('dlp_policy_violation')));
      } else if (clientSignal.aborted) {
        await cut('INCOMPLETE', 'client_closed');
      } else {
        await cut(
          'UPSTREAM_ERROR',
          error instanceof LlmUpstreamError
            ? error.detail
            : error instanceof Error
              ? error.name
              : 'stream failed',
        );
        yield sse(
          errorEvent(
            new BadGatewayException({ reason: 'llm_upstream_unavailable' }),
          ),
        );
      }
    } finally {
      idle.clear();
      void reader.cancel().catch(() => undefined);
      // The client went away while we waited on the upstream.
      if (!ended) await cut('INCOMPLETE', 'client_closed');
    }
  }
}

function applyUsage(record: CallRecord, usage: AnthropicUsage): void {
  Object.assign(record, {
    promptTokens: usage.input_tokens ?? 0,
    completionTokens: usage.output_tokens ?? 0,
    cacheCreationTokens: usage.cache_creation_input_tokens ?? 0,
    cacheReadTokens: usage.cache_read_input_tokens ?? 0,
  });
}

/** Reported tokens, else a length/4 estimate of what was sent and received (never 0). */
function tokens(
  usage: AnthropicUsage,
  sent: unknown,
  outputChars: number,
): number {
  return (
    usageTokens(usage) ||
    Math.ceil((JSON.stringify(sent).length + outputChars) / 4)
  );
}

/** Aborts when the client goes away or the upstream is silent for `ms` (reset on every chunk). */
class IdleAbort {
  private readonly controller = new AbortController();
  private timer: NodeJS.Timeout | undefined;
  readonly signal: AbortSignal;

  constructor(
    private readonly ms: number,
    client: AbortSignal,
  ) {
    this.signal = AbortSignal.any([client, this.controller.signal]);
    this.touch();
  }

  touch(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(
      () =>
        this.controller.abort(
          new DOMException('upstream idle', 'TimeoutError'),
        ),
      this.ms,
    );
  }

  clear(): void {
    clearTimeout(this.timer);
  }
}
