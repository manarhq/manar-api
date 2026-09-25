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
import type { DlpAdvisory } from '../ai-advisory/ai-advisory-client.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  EnforcementDependencyUnavailableException,
  failClosed,
} from '../common/fail-closed/fail-closed';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { AgentTaskAccessService, denied } from './agent-task-access.service';
import { applyDlpFloor } from './llm-dlp-floor';
import { LlmBudgetStore } from './llm-budget.store';
import { LlmUpstreamClient, LlmUpstreamError } from './llm-upstream.client';
import type { UpstreamChatResponse } from './llm-upstream.client';

/** OpenAI-compatible request; unknown fields are dropped, `model` is ignored (manar-api picks the model). */
export const ChatCompletionRequestSchema = z.object({
  model: z.string().optional(),
  messages: z.array(z.object({ role: z.string().min(1) }).passthrough()).min(1),
  tools: z.array(z.object({}).passthrough()).optional(),
  tool_choice: z.unknown().optional(),
  temperature: z.number().min(0).max(2).optional(),
  max_tokens: z.number().int().positive().optional(),
  stream: z.literal(false).optional(),
});
export type ChatCompletionRequest = z.infer<typeof ChatCompletionRequestSchema>;

/**
 * manar-ai finding types that block on the proxy path. E-mail/UPN and other
 * PII do not block: a SOC agent cannot reason about an incident without the
 * user's UPN, and UAE PII is already redacted by the floor. `source:
 * "system"` markers (manar-ai's AI layer did not run) never block (S7).
 */
const BLOCKING_ADVISORY_TYPES = new Set([
  'TYPE_API_KEY',
  'TYPE_PRIVATE_KEY',
  'TYPE_JWT',
  'TYPE_CREDENTIAL',
]);

export function advisoryBlocks(advisory: DlpAdvisory): boolean {
  return advisory.findings.some(
    (f) => f.source !== 'system' && BLOCKING_ADVISORY_TYPES.has(f.type),
  );
}

/** Every string leaf of the forwarded payload, for manar-ai's DLP scan. */
function textOf(value: unknown): string {
  const parts: string[] = [];
  const walk = (node: unknown): void => {
    if (typeof node === 'string') parts.push(node);
    else if (Array.isArray(node)) node.forEach(walk);
    else if (node !== null && typeof node === 'object')
      Object.values(node).forEach(walk);
  };
  walk(value);
  return parts.join('\n');
}

export class LlmBudgetExhaustedException extends HttpException {
  constructor() {
    super(
      { decision: 'DENY', reason: 'llm_budget_exhausted' },
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }
}

interface CallRecord {
  taskId: string;
  outcome: 'SUCCESS' | 'DENIED' | 'UNAVAILABLE' | 'UPSTREAM_ERROR';
  reason?: string;
  provider?: string;
  model?: string;
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  promptSha256?: string;
  latencyMs: number;
  messageCount: number;
  toolCount: number;
  dlp?: {
    floorCredentialTypes: string[];
    floorRedactedPiiTypes: string[];
    advisoryFindingTypes: string[];
  };
  budget?: { used: number; limit: number };
}

/**
 * `POST /agent/v1/llm/chat/completions` (ADR-0002). In order, each step
 * fail-closed: task access (kill switches, task assigned/live) -> token
 * budget -> deterministic DLP floor -> manar-ai DLP (a `null` blocks here)
 * -> upstream -> count usage -> audit `llm.request` (metadata only) -> reply.
 * None of this is on the authorization decision path.
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
      promptSha256: createHash('sha256')
        .update(JSON.stringify(request.messages))
        .digest('hex'),
    };

    try {
      const { tenantClient, task } = await this.access.assertTaskAccess(
        agent,
        taskId,
      );

      const limit = this.config.get('LLM_TASK_TOKEN_BUDGET', { infer: true });
      const used = await failClosed('limits-store', () =>
        this.budget.used(agent.tenant.id, task.id),
      );
      record.budget = { used, limit };
      if (used >= limit) throw new LlmBudgetExhaustedException();

      const floor = applyDlpFloor({
        messages: request.messages,
        tools: request.tools,
      });
      record.dlp = {
        floorCredentialTypes: floor.credentialTypes,
        floorRedactedPiiTypes: floor.piiTypes,
        advisoryFindingTypes: [],
      };
      if (floor.credentialTypes.length > 0) {
        throw denied('dlp_policy_violation');
      }

      const advisory = await failClosed('dlp-advisory', () =>
        this.aiAdvisory.analyzeDlp({
          content: textOf(floor.value),
          tenantId: agent.tenant.id,
        }),
      );
      if (advisory === null) {
        throw new EnforcementDependencyUnavailableException('dlp-advisory');
      }
      record.dlp.advisoryFindingTypes = [
        ...new Set(advisory.findings.map((f) => f.type)),
      ].sort();
      if (advisoryBlocks(advisory)) throw denied('dlp_policy_violation');

      let response: UpstreamChatResponse;
      try {
        response = await this.upstream.chat({
          messages: floor.value.messages,
          ...(floor.value.tools ? { tools: floor.value.tools } : {}),
          ...(request.tool_choice !== undefined
            ? { tool_choice: request.tool_choice }
            : {}),
          ...(request.temperature !== undefined
            ? { temperature: request.temperature }
            : {}),
          ...(request.max_tokens !== undefined
            ? { max_tokens: request.max_tokens }
            : {}),
        });
      } catch (error) {
        if (error instanceof LlmUpstreamError) {
          record.outcome = 'UPSTREAM_ERROR';
          record.reason = error.detail;
          throw new BadGatewayException({
            reason: 'llm_upstream_unavailable',
          });
        }
        throw error;
      }

      const usage = response.body.usage ?? {};
      const promptTokens = usage.prompt_tokens ?? 0;
      const completionTokens = usage.completion_tokens ?? 0;
      // No usage reported: charge a conservative estimate rather than nothing.
      const totalTokens =
        usage.total_tokens ??
        (promptTokens + completionTokens ||
          Math.ceil(
            (JSON.stringify(floor.value).length +
              JSON.stringify(response.body.choices).length) /
              4,
          ));
      const total = await failClosed('limits-store', () =>
        this.budget.add(agent.tenant.id, task.id, totalTokens, task.expiresAt),
      );

      Object.assign(record, {
        outcome: 'SUCCESS',
        provider: response.provider,
        model: response.body.model ?? response.model,
        promptTokens,
        completionTokens,
        totalTokens,
        latencyMs: Date.now() - started,
        budget: { used: total, limit },
      });
      // A completion the audit chain does not know about is never handed out.
      await failClosed('audit-store', () =>
        this.audit.record(tenantClient, agent.tenant.id, {
          eventType: AUDIT_EVENT_TYPES.LLM_REQUEST,
          actor: { type: 'agent', id: agent.agent.id },
          data: { ...record },
        }),
      );
      return response.body;
    } catch (error) {
      if (error instanceof HttpException && record.outcome !== 'SUCCESS') {
        if (error.getStatus() === 503) record.outcome = 'UNAVAILABLE';
        const body = error.getResponse() as { reason?: string };
        record.reason ??= body.reason;
        record.latencyMs = Date.now() - started;
        await this.recordFailure(agent, record);
      }
      throw error;
    }
  }

  private async recordFailure(
    agent: AgentContext,
    record: CallRecord,
  ): Promise<void> {
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
