import { createHmac, hkdfSync } from 'node:crypto';
import { Readable } from 'node:stream';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  BadGatewayException,
  BadRequestException,
  HttpException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { AgentContext } from '../agent-mtls/agent-context';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { failClosed } from '../common/fail-closed/fail-closed';
import { applyDlpFloor } from '../common/dlp/dlp-classification';
import { CatalogService } from '../platform/catalog.service';
import { denied } from './agent-task-access.service';
import {
  AnthropicMessagesRequestSchema,
  AnthropicStreamGuard,
  MessageAccumulator,
  type AnthropicMessagesRequest,
  clientHeaders,
  DlpBlocked,
  errorEvent,
  fromOpenAiChat,
  holdOpaque,
  messageEvents,
  parseSse,
  PING,
  requestRefusal,
  requestSlots,
  scanMessage,
  sse,
  toOpenAiChat,
  usageTokens,
  type AnthropicUsage,
} from './llm-anthropic';
import { LlmBudgetStore } from './llm-budget.store';
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
  type AnthropicProvider,
} from './llm-upstream.client';

type Json = Record<string, unknown>;
type Call = AdmittedCall<unknown>;

export type AnthropicReply =
  { json: Json } | { stream: AsyncGenerator<string>; stop?: AbortSignal };

/** While a synthesized stream waits for its upstream, a ping this often keeps the client from timing out. */
const PING_MS = 10_000;
const EVENT_END = /\r?\n\r?\n/;

/** The client left before the answer; the call is already charged and recorded `INCOMPLETE`. */
class ClientClosed extends Error {}

/**
 * `POST /agent/v1/llm/anthropic/v1/messages` (manar-edge design section 6): the Anthropic
 * Messages format for Claude Code and other Anthropic clients, through the same gates as chat
 * completions (`LlmProxyService.admit`: task access first, then this path's request checks,
 * catalog with this upstream's own residency and the tenant's pinned model, token budget, DLP
 * on every string passed on), then the upstream chosen by `LLM_ANTHROPIC_PROVIDER`, then
 * response DLP (floor) before anything reaches the agent, budget from the reported usage (cache
 * tokens included) and the `llm.request` audit.
 *
 * Streaming is passed through event by event (`AnthropicStreamGuard`); the final
 * `message_delta`/`message_stop` go out only after the call is charged and audited, and a
 * credential in the output ends the stream with an Anthropic `error` event.
 */
@Injectable()
export class LlmAnthropicService {
  /** Keys the HMACs of thinking signatures this proxy returned; derived, never the secret itself. */
  private readonly thinkingKey: Buffer;

  constructor(
    private readonly proxy: LlmProxyService,
    private readonly upstream: LlmUpstreamClient,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly catalog: CatalogService,
    private readonly store: LlmBudgetStore,
  ) {
    this.thinkingKey = Buffer.from(
      hkdfSync(
        'sha256',
        this.config.get('APPROVAL_GRANT_SIGNING_SECRET', { infer: true }),
        '',
        'manar llm thinking signature v1',
        32,
      ),
    );
  }

  private thinkingHmac(value: string): string {
    return createHmac('sha256', this.thinkingKey).update(value).digest('hex');
  }

  /** Remembers the thinking signatures of a delivered answer for this task (fail closed). */
  private rememberThinking(
    agent: AgentContext,
    call: Call,
    opaque: string[],
  ): Promise<void> {
    return failClosed('limits-store', () =>
      this.store.rememberThinking(
        agent.tenant.id,
        call.task.id,
        opaque.map((v) => this.thinkingHmac(v)),
        call.task.expiresAt,
      ),
    );
  }

  /**
   * Thinking signatures and redacted-thinking data in the request skip DLP only if this proxy
   * returned them for this task. A value matching a credential or PII pattern is refused anyway.
   */
  private async checkThinking(
    agent: AgentContext,
    taskId: string,
    opaque: string[],
  ): Promise<void> {
    if (
      opaque.some((v) => {
        const floor = applyDlpFloor(v);
        return floor.credentialTypes.length > 0 || floor.piiTypes.length > 0;
      })
    ) {
      throw denied('dlp_policy_violation');
    }
    const known = await failClosed('limits-store', () =>
      this.store.knowsThinking(
        agent.tenant.id,
        taskId,
        opaque.map((v) => this.thinkingHmac(v)),
      ),
    );
    if (!known) {
      // Anthropic's wording: Claude Code drops earlier thinking blocks and retries.
      throw new BadRequestException({
        type: 'error',
        error: {
          type: 'invalid_request_error',
          message:
            'Invalid `signature` in `thinking` block: not issued by this proxy for this task',
        },
        reason: 'unknown_thinking_signature',
      });
    }
  }

  async messages(
    agent: AgentContext,
    taskId: string,
    rawBody: unknown,
    rawHeaders: { version?: string; beta?: string },
    signal: AbortSignal,
  ): Promise<AnthropicReply> {
    const started = Date.now();
    const record: CallRecord = {
      claimedTaskIdSha256: sha256(taskId),
      outcome: 'DENIED',
      format: 'anthropic',
      latencyMs: 0,
      messageCount: 0,
      toolCount: 0,
    };
    let provider = 'none' as AnthropicProvider;
    let request!: AnthropicMessagesRequest;
    let client: { version?: string; beta?: string } = {};
    let restore!: (scanned: Json) => Json;
    let recordedAlready = false;

    try {
      // Task access first: every refusal below is recorded against a verified task.
      const call = await this.proxy.admit<Json>(
        agent,
        taskId,
        record,
        undefined,
        async () => {
          record.taskId = taskId;
          delete record.claimedTaskIdSha256;
          provider = this.upstream.anthropicProvider();
          if (provider === 'none') {
            throw new NotFoundException({ reason: 'anthropic_disabled' });
          }
          request = parseBodyOrThrow(AnthropicMessagesRequestSchema, rawBody);
          Object.assign(record, {
            stream: request.stream === true,
            messageCount: request.messages.length,
            toolCount: request.tools?.length ?? 0,
            promptSha256: sha256({
              system: request.system,
              messages: request.messages,
            }),
          });
          const refusal = requestRefusal(request);
          if (refusal) throw refusal;
          client = clientHeaders(rawHeaders, this.betas());
          if (!this.upstream.anthropicModels().includes(request.model)) {
            throw new BadRequestException({
              type: 'error',
              error: {
                type: 'invalid_request_error',
                message: `model: ${request.model.slice(0, 128)} is not served by this install`,
              },
              reason: 'llm_model_not_served',
            });
          }
          // Every top-level field passed on is scanned; `model` was checked above.
          const passed: Json = { ...request };
          delete passed.model;
          const opaque = holdOpaque(passed, requestSlots);
          restore = opaque.restore;
          await this.checkThinking(agent, taskId, opaque.values);
          return {
            prompt: opaque.held,
            fixed:
              provider === 'openai_translate'
                ? undefined
                : {
                    external: true,
                    uaeResident:
                      this.config.get('LLM_ANTHROPIC_UAE_RESIDENT', {
                        infer: true,
                      }) === 'true',
                    model: request.model,
                  },
          };
        },
      );
      const stream = request.stream === true;
      const body = { ...restore(call.dlp.value), model: request.model };

      if (provider === 'openai_translate') {
        const chat = toOpenAiChat(body as AnthropicMessagesRequest);
        // Charged and audited here, whether or not the client is still reading.
        const settled = this.upstream
          .chat(chat, call.route, signal)
          .then(
            (res) => {
              record.provider = res.provider;
              record.model = res.body.model ?? res.model;
              const message = fromOpenAiChat(res.body, record.model);
              return this.deliver(agent, call, record, message, chat, started);
            },
            async (error: unknown) => {
              if (signal.aborted) {
                await this.clientLeft(agent, call, record, chat, started);
                throw new ClientClosed();
              }
              throw upstreamFailure(record, error);
            },
          )
          .catch(async (error: unknown) => {
            recordedAlready = true;
            await this.proxy.recordRefusal(agent, record, error, started);
            throw error;
          });
        if (!stream) return { json: await settled };
        settled.catch(() => undefined); // observed by the generator; never unhandled
        return { stream: this.synthesize(settled) };
      }

      record.provider = provider;
      record.model = request.model;
      const timeoutMs = this.config.get('LLM_UPSTREAM_TIMEOUT_MS', {
        infer: true,
      });
      if (!stream) {
        let message: Json;
        try {
          message = await this.upstreamCall(record, async () => {
            const { response } = await this.upstream.anthropicMessages(
              body,
              client,
              AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
            );
            const json = (await response
              .json()
              .catch(() => null)) as Json | null;
            if (json?.type !== 'message' || !Array.isArray(json.content)) {
              throw new LlmUpstreamError('not a message');
            }
            return json;
          });
        } catch (error) {
          if (signal.aborted) {
            recordedAlready = true;
            await this.clientLeft(agent, call, record, body, started);
          }
          throw error;
        }
        return {
          json: await this.deliver(agent, call, record, message, body, started),
        };
      }

      const limits = new StreamLimits(
        timeoutMs,
        this.config.get('LLM_STREAM_MAX_MS', { infer: true }),
        signal,
      );
      try {
        const { response } = await this.upstreamCall(record, () =>
          this.upstream.anthropicMessages(body, client, limits.signal),
        );
        const run = {
          agent,
          call,
          record,
          response,
          limits,
          signal,
          sent: body,
          started,
        };
        return {
          stream:
            this.config.get('LLM_ANTHROPIC_STREAM_DLP', { infer: true }) ===
            'incremental'
              ? this.relay(run)
              : this.buffered(run),
          stop: limits.signal,
        };
      } catch (error) {
        limits.clear();
        if (signal.aborted) {
          recordedAlready = true;
          await this.clientLeft(agent, call, record, body, started);
        }
        throw error;
      }
    } catch (error) {
      if (!recordedAlready) {
        await this.proxy.recordRefusal(agent, record, error, started);
      }
      throw error;
    }
  }

  /** The client left before any answer: charge the input estimate and record `INCOMPLETE`. */
  private clientLeft(
    agent: AgentContext,
    call: Call,
    record: CallRecord,
    sent: unknown,
    started: number,
  ): Promise<void> {
    return this.cut(agent, call, record, 'INCOMPLETE', 'client_closed', {
      sent,
      outputChars: 0,
      started,
    });
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
        : this.upstream.anthropicModels();
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

  private betas(): Set<string> {
    return new Set(
      this.config
        .get('LLM_ANTHROPIC_BETAS', { infer: true })
        .split(',')
        .map((b) => b.trim())
        .filter(Boolean),
    );
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
      usageTokens(usage) ||
        estimate(usage, sent, JSON.stringify(message.content).length),
    );
    if (scanned.credentialTypes.length) throw denied('dlp_policy_violation');
    await this.rememberThinking(agent, call, scanned.opaque);
    await this.proxy.recordSuccess(agent, call.tenantClient, record, started);
    return scanned.message;
  }

  /**
   * A call that ended without a complete answer still used tokens: charge the larger of what
   * was reported and the reported input plus the output seen so far (best effort), and record why.
   */
  private async cut(
    agent: AgentContext,
    call: Call,
    record: CallRecord,
    outcome: CallRecord['outcome'],
    reason: string,
    seen: {
      usage?: AnthropicUsage;
      sent: unknown;
      outputChars: number;
      started: number;
    },
  ): Promise<void> {
    const usage = seen.usage ?? {};
    Object.assign(record, {
      outcome,
      reason,
      latencyMs: Date.now() - seen.started,
    });
    applyUsage(record, usage);
    const tokens = Math.max(
      usageTokens(usage),
      estimate(usage, seen.sent, seen.outputChars),
    );
    await this.proxy.charge(agent, call, record, tokens).catch(() => undefined);
    await this.proxy.recordFailure(agent, record);
  }

  /** `openai_translate` with `stream: true`: pings while the upstream works, then the whole message as events. */
  private async *synthesize(settled: Promise<Json>): AsyncGenerator<string> {
    try {
      let message: Json | undefined;
      while (!message) {
        message = await Promise.race([
          settled,
          sleep(PING_MS, undefined, { ref: false }),
        ]);
        if (!message) yield sse(PING);
      }
      for (const e of messageEvents(message)) yield sse(e);
    } catch (error) {
      if (error instanceof ClientClosed) return;
      if (!(error instanceof HttpException)) throw error;
      yield sse(errorEvent(error)); // already charged and recorded by `settled`
    }
  }

  /**
   * `stream: true` on `anthropic`/`azure_foundry`, `LLM_ANTHROPIC_STREAM_DLP=buffer` (default):
   * reads the whole upstream stream (pinging the client every 10 s), runs the full response DLP
   * once on the complete message, charges and audits as for a non-streaming call, then replays
   * the (redacted) message as events, or one error event.
   */
  private async *buffered(run: StreamRun): AsyncGenerator<string> {
    const { agent, call, record, limits, signal, sent, started } = run;
    const message = new MessageAccumulator();
    const reader = run.response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let ended = false;
    const cut = (outcome: CallRecord['outcome'], reason: string) => {
      ended = true;
      const seen = message.result();
      return this.cut(agent, call, record, outcome, reason, {
        usage: seen.usage ?? {},
        sent,
        outputChars: JSON.stringify(seen.content).length,
        started,
      });
    };
    let read = reader.read();
    try {
      for (;;) {
        const next = await Promise.race([
          read,
          sleep(PING_MS, null, { ref: false }),
        ]);
        if (next === null) {
          yield sse(PING);
          continue;
        }
        if (next.done)
          throw new LlmUpstreamError('stream ended before message_stop');
        limits.touch();
        buffer += decoder.decode(next.value, { stream: true });
        read = reader.read();
        let complete = false;
        for (let m = EVENT_END.exec(buffer); m; m = EVENT_END.exec(buffer)) {
          const event = parseSse(buffer.slice(0, m.index));
          buffer = buffer.slice(m.index + m[0].length);
          if (!event) continue;
          if (event.data.type === 'error') {
            const type = (event.data.error as Json | undefined)?.type;
            await cut('UPSTREAM_ERROR', `stream error: ${String(type)}`);
            yield sse(
              errorEvent(
                new BadGatewayException({ reason: 'llm_upstream_unavailable' }),
              ),
            );
            return;
          }
          message.push(event);
          if (event.data.type === 'message_stop') complete = true;
        }
        if (!complete) continue;

        ended = true;
        let delivered: Json;
        try {
          delivered = await this.deliver(
            agent,
            call,
            record,
            message.result(),
            sent,
            started,
          );
        } catch (error) {
          if (!(error instanceof HttpException)) throw error;
          await this.proxy.recordRefusal(agent, record, error, started);
          yield sse(errorEvent(error));
          return;
        }
        for (const e of messageEvents(delivered, message.finalDelta))
          yield sse(e);
        return;
      }
    } catch (error) {
      if (ended) throw error;
      yield* this.streamFailure(error, signal, limits, cut);
    } finally {
      limits.clear();
      void reader.cancel().catch(() => undefined);
      if (!ended) await cut('INCOMPLETE', limits.reason());
    }
  }

  /**
   * `stream: true` on `anthropic`/`azure_foundry`, `LLM_ANTHROPIC_STREAM_DLP=incremental`: the
   * upstream's events, through `AnthropicStreamGuard`, as they arrive.
   */
  private async *relay(run: StreamRun): AsyncGenerator<string> {
    const { agent, call, record, limits, signal, sent, started } = run;
    const guard = new AnthropicStreamGuard();
    const reader = run.response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let ended = false;
    const cut = async (outcome: CallRecord['outcome'], reason: string) => {
      ended = true;
      record.responseDlp ??= {
        credentialTypes: [],
        piiTypes: [...guard.piiTypes].sort(),
      };
      await this.cut(agent, call, record, outcome, reason, {
        usage: guard.usage,
        sent,
        outputChars: guard.outputChars,
        started,
      });
    };

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done)
          throw new LlmUpstreamError('stream ended before message_stop');
        limits.touch();
        buffer += decoder.decode(value, { stream: true });
        for (let m = EVENT_END.exec(buffer); m; m = EVENT_END.exec(buffer)) {
          const event = parseSse(buffer.slice(0, m.index));
          buffer = buffer.slice(m.index + m[0].length);
          if (!event) continue;
          if (event.data.type === 'error') {
            const type = (event.data.error as Json | undefined)?.type;
            await cut('UPSTREAM_ERROR', `stream error: ${String(type)}`);
            yield sse(
              errorEvent(
                new BadGatewayException({ reason: 'llm_upstream_unavailable' }),
              ),
            );
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
              usageTokens(guard.usage) ||
                estimate(guard.usage, sent, guard.outputChars),
            );
            await this.rememberThinking(agent, call, guard.opaque);
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
        return;
      }
      yield* this.streamFailure(error, signal, limits, cut);
    } finally {
      limits.clear();
      void reader.cancel().catch(() => undefined);
      // The client went away, or the stream was torn down while parked (`stop`).
      if (!ended) await cut('INCOMPLETE', limits.reason());
    }
  }

  /** A stream that broke before its end: record why and, if the client is still there, say so. */
  private async *streamFailure(
    error: unknown,
    signal: AbortSignal,
    limits: StreamLimits,
    cut: (outcome: CallRecord['outcome'], reason: string) => Promise<void>,
  ): AsyncGenerator<string> {
    if (signal.aborted) {
      await cut('INCOMPLETE', 'client_closed');
      return;
    }
    await cut(
      'UPSTREAM_ERROR',
      limits.deadlineHit()
        ? 'stream_deadline'
        : error instanceof LlmUpstreamError
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
}

interface StreamRun {
  agent: AgentContext;
  call: Call;
  record: CallRecord;
  response: Response;
  limits: StreamLimits;
  signal: AbortSignal;
  sent: unknown;
  started: number;
}

/**
 * The SSE body for a stream reply. When `stop` fires (client gone, idle or deadline) the stream
 * is destroyed, so a generator parked on a client that stopped reading still ends, charges and
 * records.
 */
export function replyStream(reply: {
  stream: AsyncGenerator<string>;
  stop?: AbortSignal;
}): Readable {
  const readable = Readable.from(reply.stream);
  reply.stop?.addEventListener('abort', () => readable.destroy(), {
    once: true,
  });
  return readable;
}

function applyUsage(record: CallRecord, usage: AnthropicUsage): void {
  Object.assign(record, {
    promptTokens: usage.input_tokens ?? 0,
    completionTokens: usage.output_tokens ?? 0,
    cacheCreationTokens: usage.cache_creation_input_tokens ?? 0,
    cacheReadTokens: usage.cache_read_input_tokens ?? 0,
  });
}

/**
 * Reported input (with cache) plus a length/4 estimate of the output seen; without reported
 * input, a length/4 estimate of what was sent. Never 0.
 */
function estimate(
  usage: AnthropicUsage,
  sent: unknown,
  outputChars: number,
): number {
  const input =
    (usage.input_tokens ?? 0) +
      (usage.cache_creation_input_tokens ?? 0) +
      (usage.cache_read_input_tokens ?? 0) ||
    Math.ceil(JSON.stringify(sent).length / 4);
  return Math.max(1, input + Math.ceil(outputChars / 4));
}

/**
 * Aborts a streamed upstream call when the client goes away, when the upstream is silent for
 * `idleMs` (reset on every chunk), or after `maxMs` in all.
 */
class StreamLimits {
  private readonly idle = new AbortController();
  private readonly deadline: AbortSignal;
  private timer: NodeJS.Timeout | undefined;
  readonly signal: AbortSignal;

  constructor(
    private readonly idleMs: number,
    maxMs: number,
    client: AbortSignal,
  ) {
    this.deadline = AbortSignal.timeout(maxMs);
    this.signal = AbortSignal.any([client, this.idle.signal, this.deadline]);
    this.touch();
  }

  touch(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(
      () => this.idle.abort(new DOMException('upstream idle', 'TimeoutError')),
      this.idleMs,
    );
  }

  deadlineHit(): boolean {
    return this.deadline.aborted;
  }

  /** Why the stream stopped, for a stream torn down before its end. */
  reason(): string {
    if (this.deadline.aborted) return 'stream_deadline';
    if (this.idle.signal.aborted) return 'upstream_idle';
    return 'client_closed';
  }

  clear(): void {
    clearTimeout(this.timer);
  }
}
