import { createHash } from 'node:crypto';
import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { AppConfig } from '../config/env.validation';
import type { AuthContext } from '../auth/auth-context';
import { AiAdvisoryClient } from '../ai-advisory/ai-advisory-client.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { classifyDlp } from '../common/dlp/dlp-classification';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  LlmUpstreamClient,
  LlmUpstreamError,
} from '../agent-runtime/llm-upstream.client';
import { chargedTokens } from '../agent-runtime/llm-upstream.client';
import {
  CatalogService,
  catalogGate,
  type LlmRoute,
} from '../platform/catalog.service';
import { failClosed } from '../common/fail-closed/fail-closed';
import { RedisThrottlerStorageService } from '../rate-limit/redis-throttler-storage.service';
import { AiTelemetryService } from '../ai-telemetry/ai-telemetry.service';
import { AssistantReader } from './assistant-reader.service';
import { cleanAnswer, dataBlock, systemPrompt } from './assistant.prompt';
import {
  ASSISTANT_TOOLS,
  toolSchemas,
  type AssistantSource,
  type AssistantSuggestion,
  type ToolContext,
} from './assistant.tools';
import type { AssistantLocale } from './assistant.knowledge';

export const AssistantChatSchema = z
  .object({
    messages: z
      .array(
        z
          .object({
            role: z.enum(['user', 'assistant']),
            content: z.string().min(1).max(4000),
          })
          .strict(),
      )
      .min(1)
      .max(20)
      .refine((m) => m[m.length - 1]?.role === 'user', {
        message: 'the last message must be from the user',
      }),
    locale: z.enum(['en', 'ar']).default('en'),
    /** Console path the operator is on, e.g. `/incidents/<uuid>`. */
    page: z
      .string()
      .max(120)
      .regex(/^(\/[a-z0-9-]+)+$/i)
      .optional(),
  })
  .strict();

export type AssistantChatResponse =
  | {
      available: true;
      answer: string;
      sources: AssistantSource[];
      suggestions: AssistantSuggestion[];
      toolsUsed: string[];
    }
  | { available: false; reason: 'model_unavailable' };

/** ponytail: fixed per-user limit; make it config if pilots ask for a different one. */
export const ASSISTANT_RATE_LIMIT = { limit: 12, ttlMs: 60_000 };
/** Model turns per question (tool rounds plus the final answer). */
const MAX_ROUNDS = 5;
const MAX_CALLS_PER_ROUND = 4;

const DLP_REFUSAL: Record<AssistantLocale, string> = {
  en: 'Your message looks like it contains a credential or other sensitive value, so it was not sent to the model. Remove it and ask again.',
  ar: 'يبدو أن رسالتك تحتوي على بيانات اعتماد أو قيمة حساسة، لذلك لم تُرسل إلى النموذج. احذفها واسأل مرة أخرى.',
};

const WITHHELD = {
  withheld: true,
  reason:
    'Data loss prevention found credential-shaped or sensitive content in this record, so it is not shown to the assistant. The operator can open the source page to read it.',
};

/** What the streaming endpoint wants to hear while a question is answered. */
export interface ChatHooks {
  /** Everything that can fail with a normal HTTP status has passed; a model call comes next. */
  onReady?: () => void;
  /** Each piece of the answer text as the model writes it. */
  onToken?: (text: string) => void;
  /** The model asked for these tools: the text so far was thinking aloud, not the answer. */
  onTools?: (names: string[]) => void;
  /** Aborts the model call (the person pressed stop or closed the page). */
  signal?: AbortSignal;
}

/** A positive number from config, else `fallback` (test doubles return strings for every key). */
const positive = (value: unknown, fallback: number): number => {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

/** Tools that act on what other tools in the same round read: they run after those finish. */
const RUNS_AFTER_READS = new Set(['prepare_for_human']);

interface ToolCall {
  id?: string;
  function?: { name?: string; arguments?: string };
}
interface ModelMessage {
  content?: string | null;
  tool_calls?: ToolCall[];
}

/**
 * `POST /assistant/chat` (manar-api ADR-0008). Read-only, runs as the
 * signed-in human, never on the decision path. Logs and audit carry
 * metadata only: never the question, the answer or any tool output.
 */
@Injectable()
export class AssistantService {
  constructor(
    private readonly reader: AssistantReader,
    private readonly upstream: LlmUpstreamClient,
    private readonly aiAdvisory: AiAdvisoryClient,
    private readonly throttle: RedisThrottlerStorageService,
    private readonly audit: AuditService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly catalog: CatalogService,
    private readonly telemetry: AiTelemetryService,
  ) {}

  async chat(
    auth: AuthContext,
    authorization: string,
    rawBody: unknown,
    hooks?: ChatHooks,
  ): Promise<AssistantChatResponse> {
    const body = parseBodyOrThrow(AssistantChatSchema, rawBody);
    await this.enforceRateLimit(auth);
    const { route, quota } = await catalogGate(() =>
      this.catalog.llmGate(auth.tenant.id, 'assistant'),
    );
    const budget = { quota, spent: false };
    hooks?.onReady?.();

    const started = Date.now();
    const locale = body.locale;
    const meta = {
      outcome: 'ANSWERED' as string,
      locale,
      rounds: 0,
      toolCalls: [] as string[],
      rejectedToolCalls: 0,
      dlpWithheld: 0,
      dlpRedacted: 0,
      sourceCount: 0,
      promptSha256: createHash('sha256')
        .update(JSON.stringify(body.messages))
        .digest('hex'),
      latencyMs: 0,
    };
    const analyze = (content: string) =>
      this.aiAdvisory
        .analyzeDlp({ content, tenantId: auth.tenant.id })
        .catch(() => null);

    try {
      const question = await classifyDlp(body.messages, analyze);
      if (question.blocked) {
        meta.outcome = 'DLP_BLOCKED';
        return {
          available: true,
          answer: DLP_REFUSAL[locale],
          sources: [],
          suggestions: [],
          toolsUsed: [],
        };
      }

      const sources: AssistantSource[] = [];
      const suggestions: AssistantSuggestion[] = [];
      const ctx: ToolContext = {
        read: (path) => this.reader.get(path, authorization),
        cite: (source) => {
          const existing = sources.find(
            (s) => s.kind === source.kind && s.id === source.id,
          );
          if (existing) return existing.ref;
          const ref = sources.length + 1;
          sources.push({ ...source, ref });
          return ref;
        },
        seen: new Set(),
        suggest: (s) => {
          if (suggestions.length < 3) suggestions.push(s);
        },
        locale,
        now: new Date(),
      };

      const messages: unknown[] = [
        {
          role: 'system',
          content: systemPrompt({ locale, now: ctx.now, page: body.page }),
        },
        ...question.value,
      ];
      const tools = toolSchemas();
      let answer = '';

      for (let round = 0; round < MAX_ROUNDS; round++) {
        meta.rounds = round + 1;
        const last = round === MAX_ROUNDS - 1;
        const reply = await this.callModel(
          auth.tenant.id,
          route,
          budget,
          messages,
          last ? undefined : tools,
          hooks,
        );
        const calls = reply.tool_calls?.slice(0, MAX_CALLS_PER_ROUND) ?? [];
        if (calls.length === 0 || last) {
          answer = cleanAnswer(reply.content ?? '');
          break;
        }
        messages.push({
          role: 'assistant',
          content: reply.content ?? '',
          tool_calls: calls,
        });
        hooks?.onTools?.(calls.map((c) => c.function?.name ?? ''));
        // Independent reads run together; a tool that acts on what the others read waits for them.
        const outputs = new Array<{
          name: string;
          dlp: Awaited<ReturnType<typeof classifyDlp>>;
        }>(calls.length);
        const run = async (call: ToolCall, at: number): Promise<void> => {
          const name = call.function?.name ?? '';
          const output = await this.runTool(
            name,
            call.function?.arguments,
            ctx,
            meta,
          );
          outputs[at] = { name, dlp: await classifyDlp(output, analyze) };
        };
        const isLate = (c: ToolCall) =>
          RUNS_AFTER_READS.has(c.function?.name ?? '');
        await Promise.all(
          calls.flatMap((c, at) => (isLate(c) ? [] : [run(c, at)])),
        );
        for (const [at, c] of calls.entries()) {
          if (isLate(c)) await run(c, at);
        }
        for (const [at, call] of calls.entries()) {
          const { name, dlp } = outputs[at]!;
          if (dlp.blocked) meta.dlpWithheld++;
          if (
            dlp.piiTypes.length ||
            Object.keys(dlp.advisoryRedactedCounts).length
          )
            meta.dlpRedacted++;
          messages.push({
            role: 'tool',
            tool_call_id: call.id ?? name,
            name,
            content: dataBlock(name, dlp.blocked ? WITHHELD : dlp.value),
          });
        }
      }

      // A citation must point at a record that was actually read.
      const known = new Set(sources.map((s) => s.ref));
      answer = answer
        .replace(/\s?\[(\d{1,3})\]/g, (m, n: string) =>
          known.has(Number(n)) ? m : '',
        )
        .trim();
      const cited = new Set(
        [...answer.matchAll(/\[(\d{1,3})\]/g)].map((m) => Number(m[1])),
      );
      const shown = sources.filter((s) => cited.has(s.ref));
      const finalSources = (shown.length > 0 ? shown : sources).slice(0, 8);
      meta.sourceCount = finalSources.length;
      if (!answer) meta.outcome = 'EMPTY_ANSWER';
      return {
        available: true,
        answer,
        sources: finalSources,
        suggestions,
        toolsUsed: [...new Set(meta.toolCalls)],
      };
    } catch (error) {
      if (error instanceof LlmUpstreamError) {
        meta.outcome = 'MODEL_UNAVAILABLE';
        return { available: false, reason: 'model_unavailable' };
      }
      meta.outcome = 'ERROR';
      throw error;
    } finally {
      meta.latencyMs = Date.now() - started;
      await this.recordAudit(auth, meta);
    }
  }

  /** The only place a tool runs. Unknown names and bad arguments come back to the model as errors. */
  private async runTool(
    name: string,
    rawArgs: string | undefined,
    ctx: ToolContext,
    meta: { toolCalls: string[]; rejectedToolCalls: number },
  ): Promise<unknown> {
    const tool = ASSISTANT_TOOLS.find((t) => t.name === name);
    if (!tool) {
      meta.rejectedToolCalls++;
      return {
        error: 'unknown_tool',
        availableTools: ASSISTANT_TOOLS.map((t) => t.name),
      };
    }
    let args: unknown;
    try {
      args = rawArgs ? JSON.parse(rawArgs) : {};
    } catch {
      meta.rejectedToolCalls++;
      return { error: 'arguments_not_json' };
    }
    const parsed = tool.params.safeParse(args);
    if (!parsed.success) {
      meta.rejectedToolCalls++;
      return {
        error: 'invalid_arguments',
        issues: parsed.error.issues.map(
          (i) => `${i.path.join('.')}: ${i.message}`,
        ),
      };
    }
    meta.toolCalls.push(name);
    return await tool.run(parsed.data as never, ctx);
  }

  private async callModel(
    tenantId: string,
    route: LlmRoute['route'],
    budget: { quota: number | null; spent: boolean },
    messages: unknown[],
    tools: ReturnType<typeof toolSchemas> | undefined,
    hooks?: ChatHooks,
  ): Promise<ModelMessage> {
    // A chat runs several model rounds; once the month's quota is spent, the next one is refused.
    if (budget.spent)
      throw new ForbiddenException({
        decision: 'DENY',
        reason: 'llm_token_quota_exhausted',
      });
    const provider =
      route?.provider ?? this.config.get('LLM_PROVIDER', { infer: true });
    const ollama = provider === 'ollama';
    const request = {
      messages,
      ...(tools ? { tools, tool_choice: 'auto' } : {}),
      // Small local models answer faster and stay on task without a thinking pass.
      ...(ollama
        ? { reasoning_effort: 'none' as const, temperature: 0.2 }
        : {}),
    };
    // One round is bounded far below the agents' 180 s proxy timeout: a stuck round fails fast.
    const roundMs = positive(
      this.config.get('ASSISTANT_LLM_ROUND_TIMEOUT_MS', { infer: true }),
      45_000,
    );
    const idleMs = positive(
      this.config.get('LLM_STREAM_IDLE_MS', { infer: true }),
      20_000,
    );
    const started = Date.now();
    let firstToken: number | undefined;
    const call = {
      tenantId,
      feature: 'assistant' as const,
      provider: String(provider ?? 'unknown'),
      model: route?.model ?? 'unknown',
      inputTokens: 0,
      outputTokens: 0,
    };
    let response;
    try {
      response = hooks?.onToken
        ? await this.upstream.chatStream(
            request,
            route,
            (text) => {
              firstToken ??= Date.now() - started;
              hooks.onToken?.(text);
            },
            {
              signal: hooks.signal,
              firstTokenMs: roundMs,
              idleMs,
              totalMs: roundMs * 2,
            },
          )
        : await this.upstream.chat(request, route, hooks?.signal, roundMs);
    } catch (error) {
      void this.telemetry.record({
        ...call,
        latencyMs: Date.now() - started,
        outcome: hooks?.signal?.aborted ? 'cancelled' : 'unavailable',
      });
      throw error;
    }
    const usage = response.body.usage;
    const contentChars = JSON.stringify(response.body.choices ?? '').length;
    void this.telemetry.record({
      ...call,
      provider: response.provider,
      model: response.model,
      inputTokens:
        usage?.prompt_tokens ?? Math.ceil(JSON.stringify(messages).length / 4),
      outputTokens: usage?.completion_tokens ?? Math.ceil(contentChars / 4),
      latencyMs: Date.now() - started,
      firstTokenMs: firstToken,
      outcome: 'ok',
    });
    // Counts toward the tenant's monthly quota; an unwritable counter refuses the answer.
    const monthTotal = await failClosed('limits-store', () =>
      this.catalog.recordTokens(tenantId, chargedTokens(response, messages)),
    );
    if (budget.quota !== null && monthTotal >= budget.quota)
      budget.spent = true;
    const choices = response.body.choices as
      { message?: ModelMessage }[] | undefined;
    return choices?.[0]?.message ?? {};
  }

  private async enforceRateLimit(auth: AuthContext): Promise<void> {
    let hits: number;
    let retryAfter: number;
    try {
      const record = await this.throttle.increment(
        `${auth.tenant.id}:${auth.user.id}`,
        ASSISTANT_RATE_LIMIT.ttlMs,
        ASSISTANT_RATE_LIMIT.limit,
        0,
        'assistant',
      );
      hits = record.totalHits;
      retryAfter = record.timeToExpire;
    } catch {
      throw new HttpException(
        { reason: 'assistant_rate_limit_unavailable' },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
    if (hits > ASSISTANT_RATE_LIMIT.limit) {
      throw new HttpException(
        { reason: 'assistant_rate_limited', retryAfterSeconds: retryAfter },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private async recordAudit(
    auth: AuthContext,
    meta: Record<string, unknown>,
  ): Promise<void> {
    try {
      const tenantClient = await this.tenantDatabaseManager.getClient(
        auth.tenant.id,
      );
      await this.audit.recordSafely(tenantClient, auth.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.ASSISTANT_REQUEST,
        actor: { type: 'human', id: auth.user.id },
        data: meta,
      });
    } catch {
      // Best effort: the assistant changes nothing, so a missing record loses no control.
    }
  }
}
