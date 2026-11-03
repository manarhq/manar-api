import { createHash } from 'node:crypto';
import {
  BadGatewayException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { AppConfig } from '../config/env.validation';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AiAdvisoryClient } from '../ai-advisory/ai-advisory-client.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  EnforcementDependencyUnavailableException,
  failClosed,
} from '../common/fail-closed/fail-closed';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { AgentTaskAccessService, denied } from './agent-task-access.service';
import { classifyDlp } from '../common/dlp/dlp-classification';
import { LlmBudgetStore } from './llm-budget.store';
import { CatalogService, catalogGate } from '../platform/catalog.service';
import {
  chargedTokens,
  LlmUpstreamClient,
  LlmUpstreamError,
} from './llm-upstream.client';
import type {
  LlmRouteOverride,
  UpstreamChatResponse,
} from './llm-upstream.client';
import type { DlpClassification } from '../common/dlp/dlp-classification';
import type { TaskRecord } from '../tasks/tasks.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/** OpenAI-compatible request; unknown fields are dropped, `model` is ignored (manar-api picks the model). */
export const ChatCompletionRequestSchema = z.object({
  model: z.string().optional(),
  messages: z.array(z.object({ role: z.string().min(1) }).passthrough()).min(1),
  tools: z.array(z.object({}).passthrough()).optional(),
  tool_choice: z.unknown().optional(),
  temperature: z.number().min(0).max(2).optional(),
  max_tokens: z.number().int().positive().optional(),
  /** How hard a reasoning model thinks. `none` turns thinking off where the provider can. */
  reasoning_effort: z
    .enum(['none', 'minimal', 'low', 'medium', 'high'])
    .optional(),
  stream: z.literal(false).optional(),
});
export type ChatCompletionRequest = z.infer<typeof ChatCompletionRequestSchema>;

export class LlmBudgetExhaustedException extends HttpException {
  constructor() {
    super(
      { decision: 'DENY', reason: 'llm_budget_exhausted' },
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }
}

/** The `llm.request` audit payload: metadata only, never prompt or completion text. */
export interface CallRecord {
  /** Set once the task access check passed (the Anthropic path never records an unverified id). */
  taskId?: string;
  /** Anthropic path, refused before the task was verified: SHA-256 of the id the agent sent. */
  claimedTaskIdSha256?: string;
  outcome:
    'SUCCESS' | 'DENIED' | 'UNAVAILABLE' | 'UPSTREAM_ERROR' | 'INCOMPLETE';
  reason?: string;
  /** Absent: OpenAI chat completions. */
  format?: 'anthropic';
  stream?: boolean;
  provider?: string;
  model?: string;
  promptTokens?: number;
  completionTokens?: number;
  cacheCreationTokens?: number;
  cacheReadTokens?: number;
  totalTokens?: number;
  promptSha256?: string;
  latencyMs: number;
  messageCount: number;
  toolCount: number;
  dlp?: {
    floorCredentialTypes: string[];
    floorRedactedPiiTypes: string[];
    advisoryFindingTypes: string[];
    advisoryRedactedCounts: Record<string, number>;
  };
  /** Model output checked before it reaches the agent (Anthropic format): floor types found. */
  responseDlp?: { credentialTypes: string[]; piiTypes: string[] };
  budget?: { used: number; limit: number };
}

/** What passed the gates in front of a model call. */
export interface AdmittedCall<T> {
  tenantClient: TenantPrismaClient;
  task: TaskRecord;
  /** Where tokens are counted: the root of the task's delegation chain, so children share one budget. */
  budgetTask: Pick<TaskRecord, 'id' | 'expiresAt'>;
  /** The tenant's catalog model; null = the deployment default. */
  route: LlmRouteOverride | null;
  limit: number;
  /** The prompt after DLP: what may be sent upstream. */
  dlp: DlpClassification<T>;
}

/**
 * `POST /agent/v1/llm/chat/completions` (ADR-0002). In order, each step
 * fail-closed: task access (kill switches, task assigned/live, pack enabled) -> the tenant's
 * catalog (proxy on, model allowed, monthly quota) -> token budget -> DLP (floor, manar-ai with a `null` blocking here, generic PII redacted per leaf)
 * -> upstream -> count usage -> audit `llm.request` (metadata only) -> reply.
 * None of this is on the authorization decision path. The Anthropic-format proxy
 * (`LlmAnthropicService`) runs the same steps through `admit`, `charge`, `recordSuccess` and
 * `recordRefusal`.
 */
@Injectable()
export class LlmProxyService {
  constructor(
    private readonly access: AgentTaskAccessService,
    private readonly budget: LlmBudgetStore,
    private readonly upstream: LlmUpstreamClient,
    private readonly aiAdvisory: AiAdvisoryClient,
    private readonly audit: AuditService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly catalog: CatalogService,
  ) {}

  async complete(
    agent: AgentContext,
    taskId: string,
    rawBody: unknown,
  ): Promise<UpstreamChatResponse['body']> {
    const request = parseBodyOrThrow(ChatCompletionRequestSchema, rawBody);
    const started = Date.now();
    const record: CallRecord = {
      taskId,
      outcome: 'DENIED',
      latencyMs: 0,
      messageCount: request.messages.length,
      toolCount: request.tools?.length ?? 0,
      promptSha256: sha256(request.messages),
    };

    try {
      const call = await this.admit(agent, taskId, record, {
        messages: request.messages,
        tools: request.tools,
      });
      const { value } = call.dlp;

      let response: UpstreamChatResponse;
      try {
        response = await this.upstream.chat(
          {
            messages: value.messages,
            ...(value.tools ? { tools: value.tools } : {}),
            ...(request.tool_choice !== undefined
              ? { tool_choice: request.tool_choice }
              : {}),
            ...(request.temperature !== undefined
              ? { temperature: request.temperature }
              : {}),
            ...(request.max_tokens !== undefined
              ? { max_tokens: request.max_tokens }
              : {}),
            ...(request.reasoning_effort !== undefined
              ? { reasoning_effort: request.reasoning_effort }
              : {}),
          },
          call.route,
        );
      } catch (error) {
        throw upstreamFailure(record, error);
      }

      const usage = response.body.usage ?? {};
      // No usage reported: charge a conservative estimate rather than nothing.
      await this.charge(agent, call, record, chargedTokens(response, value));
      Object.assign(record, {
        outcome: 'SUCCESS',
        provider: response.provider,
        model: response.body.model ?? response.model,
        promptTokens: usage.prompt_tokens ?? 0,
        completionTokens: usage.completion_tokens ?? 0,
      });
      await this.recordSuccess(agent, call.tenantClient, record, started);
      return response.body;
    } catch (error) {
      await this.recordRefusal(agent, record, error, started);
      throw error;
    }
  }

  /**
   * The gates before any model call, in order: task access, then `afterAccess` (the caller's
   * own checks; it may supply the prompt and name a fixed upstream outside the catalog, judged
   * by its own placement and the tenant's pinned model), the tenant's catalog, the task's token
   * budget, DLP on the prompt (everything the model will read). Throws the refusal; `record`
   * carries what was found.
   */
  async admit<T>(
    agent: AgentContext,
    taskId: string,
    record: CallRecord,
    prompt: T | undefined,
    afterAccess?: () => Promise<{
      prompt?: T;
      fixed?: { external: boolean; uaeResident: boolean; model: string };
    }>,
  ): Promise<AdmittedCall<T>> {
    const { tenantClient, task, budgetTask } =
      await this.access.assertTaskAccess(agent, taskId);
    const after = await afterAccess?.();
    const fixed = after?.fixed;
    prompt = after?.prompt ?? prompt;

    // Staff's catalog: proxy on, model allowed for this tenant, monthly quota left.
    const { route } = await catalogGate(() =>
      this.catalog.llmGate(agent.tenant.id, 'llm_proxy', fixed),
    );

    const limit = this.config.get('LLM_TASK_TOKEN_BUDGET', { infer: true });
    const used = await failClosed('limits-store', () =>
      this.budget.used(agent.tenant.id, budgetTask.id),
    );
    record.budget = { used, limit };
    if (used >= limit) throw new LlmBudgetExhaustedException();

    const dlp = await classifyDlp(prompt as T, (content) =>
      failClosed('dlp-advisory', () =>
        this.aiAdvisory.analyzeDlp({ content, tenantId: agent.tenant.id }),
      ),
    );
    record.dlp = {
      floorCredentialTypes: dlp.credentialTypes,
      floorRedactedPiiTypes: dlp.piiTypes,
      advisoryFindingTypes: [
        ...new Set(dlp.advisory?.findings.map((f) => f.type) ?? []),
      ].sort(),
      advisoryRedactedCounts: dlp.advisoryRedactedCounts,
    };
    if (dlp.advisory === null) {
      throw new EnforcementDependencyUnavailableException('dlp-advisory');
    }
    if (dlp.blocked) throw denied('dlp_policy_violation');
    return { tenantClient, task, budgetTask, route, limit, dlp };
  }

  /** Adds the tokens a call used to the task budget and the tenant's monthly count (fail closed). */
  async charge(
    agent: AgentContext,
    call: Pick<AdmittedCall<unknown>, 'budgetTask' | 'limit'>,
    record: CallRecord,
    tokens: number,
  ): Promise<void> {
    const total = await failClosed('limits-store', () =>
      this.budget.add(
        agent.tenant.id,
        call.budgetTask.id,
        tokens,
        call.budgetTask.expiresAt,
      ),
    );
    record.totalTokens = tokens;
    record.budget = { used: total, limit: call.limit };
    await failClosed('limits-store', () =>
      this.catalog.recordTokens(agent.tenant.id, tokens),
    );
  }

  /** A completion the audit chain does not know about is never handed out: throws 503 if not written. */
  async recordSuccess(
    agent: AgentContext,
    tenantClient: TenantPrismaClient,
    record: CallRecord,
    started: number,
  ): Promise<void> {
    record.outcome = 'SUCCESS';
    record.latencyMs = Date.now() - started;
    await failClosed('audit-store', () =>
      this.audit.record(tenantClient, agent.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.LLM_REQUEST,
        actor: { type: 'agent', id: agent.agent.id },
        data: { ...record },
      }),
    );
  }

  /** Records a refused call (best effort) when `error` is the HTTP refusal; the caller rethrows. */
  async recordRefusal(
    agent: AgentContext,
    record: CallRecord,
    error: unknown,
    started: number,
  ): Promise<void> {
    if (error instanceof HttpException && record.outcome !== 'SUCCESS') {
      if (error.getStatus() === 503) record.outcome = 'UNAVAILABLE';
      const body = error.getResponse() as { reason?: string };
      record.reason ??= body.reason;
      record.latencyMs = Date.now() - started;
      await this.recordFailure(agent, record);
    }
  }

  /** Best effort: the call is refused or cut either way. */
  async recordFailure(agent: AgentContext, record: CallRecord): Promise<void> {
    try {
      const tenantClient = await this.tenantDatabaseManager.getClient(
        agent.tenant.id,
      );
      await this.audit.recordSafely(tenantClient, agent.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.LLM_REQUEST,
        actor: { type: 'agent', id: agent.agent.id },
        data: { ...record },
      });
    } catch {
      // The call is refused either way; the refusal itself is the control.
    }
  }
}

export function sha256(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

/** An `LlmUpstreamError` becomes 502 `llm_upstream_unavailable` (recorded as UPSTREAM_ERROR). */
export function upstreamFailure(record: CallRecord, error: unknown): unknown {
  if (!(error instanceof LlmUpstreamError)) return error;
  record.outcome = 'UPSTREAM_ERROR';
  record.reason = error.detail;
  return new BadGatewayException({ reason: 'llm_upstream_unavailable' });
}
