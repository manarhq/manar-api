import { describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { AgentContext } from '../agent-mtls/agent-context';
import type {
  AiAdvisoryClient,
  DlpAdvisory,
} from '../ai-advisory/ai-advisory-client.service';
import type { AuditService } from '../audit/audit.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { KillSwitchService } from '../kill-switches/kill-switch.service';
import { TasksService } from '../tasks/tasks.service';
import type { TaskRecord } from '../tasks/tasks.service';
import { AgentTaskAccessService } from './agent-task-access.service';
import type { LlmBudgetStore } from './llm-budget.store';
import { LlmProxyService } from './llm-proxy.service';
import type { LlmUpstreamClient } from './llm-upstream.client';

const AGENT: AgentContext = {
  tenant: { id: 'tenant-1', slug: 't' },
  agent: { id: 'agent-1', slug: 'a', identifier: 'agent://t/a' },
  certificate: { serialNumber: 'AB' },
};

const SECRET_PROMPT = 'Summarise incident 4201 for alice@contoso.example';
const COMPLETION = 'The incident shows credential dumping on fx-ws-042.';

function makeTask(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: 'task-1',
    name: 'n',
    description: null,
    parentTaskId: null,
    requesterId: 'u',
    assignedAgentId: 'agent-1',
    status: 'ACTIVE',
    startsAt: new Date(Date.now() - 60_000),
    expiresAt: new Date(Date.now() + 3_600_000),
    maxExecutions: null,
    executionCount: 0,
    allowedToolActions: [],
    allowedResourceSelectors: [],
    forbiddenActions: [],
    riskCeiling: 20,
    createdAt: new Date(),
    ...overrides,
  };
}

const CLEAN: DlpAdvisory = { findings: [], overallSeverity: 'SEVERITY_NONE' };

function setup(
  opts: {
    task?: TaskRecord | null;
    killed?: string;
    advisory?: DlpAdvisory | null;
    used?: number;
    budget?: number;
    killSwitchDown?: boolean;
  } = {},
) {
  const task = opts.task === undefined ? makeTask() : opts.task;
  const tenantClient = {
    task: { findUnique: vi.fn().mockResolvedValue(task) },
  };
  const tenantDatabaseManager = {
    getClient: vi.fn().mockResolvedValue(tenantClient),
  } as unknown as TenantDatabaseManager;
  const killSwitchService = {
    checkAll: opts.killSwitchDown
      ? vi.fn().mockRejectedValue(new Error('control db down'))
      : vi
          .fn()
          .mockResolvedValue(
            opts.killed
              ? { killed: true, scope: 'AGENT', reason: opts.killed }
              : { killed: false },
          ),
  } as unknown as KillSwitchService;
  const access = new AgentTaskAccessService(
    tenantDatabaseManager,
    killSwitchService,
    new TasksService(null as never, null as never),
  );
  const budget = {
    used: vi.fn().mockResolvedValue(opts.used ?? 0),
    add: vi
      .fn()
      .mockImplementation((_t, _k, n: number) => (opts.used ?? 0) + n),
  };
  const upstream = {
    chat: vi.fn().mockResolvedValue({
      provider: 'ollama',
      model: 'qwen3.5:9b',
      body: {
        id: 'chatcmpl-1',
        object: 'chat.completion',
        model: 'qwen3.5:9b',
        choices: [
          {
            index: 0,
            message: { role: 'assistant', content: COMPLETION },
            finish_reason: 'stop',
          },
        ],
        usage: { prompt_tokens: 40, completion_tokens: 12, total_tokens: 52 },
      },
    }),
  };
  const aiAdvisory = {
    analyzeDlp: vi
      .fn()
      .mockResolvedValue(opts.advisory === undefined ? CLEAN : opts.advisory),
  };
  const audit = {
    record: vi.fn().mockResolvedValue({}),
    recordSafely: vi.fn().mockResolvedValue({}),
  };
  const values: Record<string, unknown> = {
    LLM_TASK_TOKEN_BUDGET: opts.budget ?? 200_000,
  };
  const config = {
    get: (k: string) => values[k],
  } as unknown as ConfigService<AppConfig, true>;
  const service = new LlmProxyService(
    access,
    budget as unknown as LlmBudgetStore,
    upstream as unknown as LlmUpstreamClient,
    aiAdvisory as unknown as AiAdvisoryClient,
    audit as unknown as AuditService,
    tenantDatabaseManager,
    config,
  );
  return { service, upstream, aiAdvisory, audit, budget };
}

const body = (content = SECRET_PROMPT) => ({
  model: 'anything',
  messages: [{ role: 'user', content }],
});

async function expectDeny(
  promise: Promise<unknown>,
  status: number,
  reason: string,
): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    status,
    response: expect.objectContaining({ reason }) as unknown,
  });
}

describe('LlmProxyService', () => {
  it('forwards a clean prompt and returns the upstream completion', async () => {
    const { service, upstream, budget } = setup();
    const result = await service.complete(AGENT, 'task-1', body());
    expect(result).toMatchObject({
      choices: [{ message: { content: COMPLETION } }],
    });
    expect(upstream.chat).toHaveBeenCalledWith({
      messages: [{ role: 'user', content: SECRET_PROMPT }],
    });
    expect(budget.add).toHaveBeenCalledWith(
      'tenant-1',
      'task-1',
      52,
      expect.any(Date),
    );
  });

  it('denies a task assigned to another agent, without calling upstream', async () => {
    const { service, upstream } = setup({
      task: makeTask({ assignedAgentId: 'someone-else' }),
    });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      403,
      'not_assigned_agent',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('denies an unknown task', async () => {
    const { service, upstream } = setup({ task: null });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      403,
      'task_not_found',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('denies an expired task', async () => {
    const { service, upstream } = setup({
      task: makeTask({ expiresAt: new Date(Date.now() - 1000) }),
    });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      403,
      'task_outside_time_window',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('denies a revoked task', async () => {
    const { service } = setup({ task: makeTask({ status: 'REVOKED' }) });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      403,
      'task_status_revoked',
    );
  });

  it('denies when a kill switch is active', async () => {
    const { service, upstream } = setup({ killed: 'agent_kill_switch_active' });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      403,
      'agent_kill_switch_active',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('fails closed when the kill-switch store is down', async () => {
    const { service, upstream } = setup({ killSwitchDown: true });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      503,
      'enforcement_dependency_unavailable',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('blocks (503, fail closed) when the DLP advisory is unavailable', async () => {
    const { service, upstream } = setup({ advisory: null });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      503,
      'enforcement_dependency_unavailable',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('blocks a secret the deterministic floor finds even when the advisory says clean', async () => {
    const { service, upstream, aiAdvisory } = setup({ advisory: CLEAN });
    await expectDeny(
      service.complete(
        AGENT,
        'task-1',
        body(
          'use this: {"client_secret": "Abc8Q~0123456789abcdefghijklmnopqrstuvwx"}',
        ),
      ),
      403,
      'dlp_policy_violation',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
    expect(aiAdvisory.analyzeDlp).not.toHaveBeenCalled();
  });

  it('blocks when the advisory reports a credential', async () => {
    const { service, upstream } = setup({
      advisory: {
        overallSeverity: 'SEVERITY_HIGH',
        findings: [
          {
            type: 'TYPE_API_KEY',
            confidence: 0.9,
            redactedPreview: 'sk-...',
            source: 'regex',
          },
        ],
      },
    });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      403,
      'dlp_policy_violation',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('does not block on e-mail findings or the "AI layer did not run" marker (S7)', async () => {
    const { service, upstream } = setup({
      advisory: {
        overallSeverity: 'SEVERITY_HIGH',
        findings: [
          {
            type: 'TYPE_EMAIL',
            confidence: 0.9,
            redactedPreview: 'a...',
            source: 'regex',
          },
          {
            type: 'TYPE_OTHER',
            confidence: 0,
            redactedPreview: 'x',
            source: 'system',
          },
        ],
      },
    });
    await service.complete(AGENT, 'task-1', body());
    expect(upstream.chat).toHaveBeenCalledOnce();
  });

  it('redacts UAE PII before the prompt leaves manar-api', async () => {
    const { service, upstream, aiAdvisory } = setup();
    await service.complete(
      AGENT,
      'task-1',
      body('Holder 784-1990-1234567-1, IBAN AE070331234567890123456'),
    );
    const sent = JSON.stringify(upstream.chat.mock.calls[0]);
    expect(sent).not.toContain('784-1990-1234567-1');
    expect(sent).not.toContain('AE070331234567890123456');
    expect(sent).toContain('[REDACTED:EMIRATES_ID]');
    expect(sent).toContain('[REDACTED:UAE_IBAN]');
    expect(JSON.stringify(aiAdvisory.analyzeDlp.mock.calls)).not.toContain(
      '784-1990',
    );
  });

  it('refuses with 429 llm_budget_exhausted once the task budget is used', async () => {
    const { service, upstream } = setup({ used: 1000, budget: 1000 });
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      429,
      'llm_budget_exhausted',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('fails closed when the budget store is down', async () => {
    const { service, budget, upstream } = setup();
    budget.used.mockRejectedValue(new Error('ECONNREFUSED'));
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      503,
      'enforcement_dependency_unavailable',
    );
    expect(upstream.chat).not.toHaveBeenCalled();
  });

  it('audits llm.request with metadata only, never prompt or completion content', async () => {
    const { service, audit } = setup();
    await service.complete(AGENT, 'task-1', body());
    expect(audit.record).toHaveBeenCalledOnce();
    const event = audit.record.mock.calls[0]?.[2] as {
      eventType: string;
      data: Record<string, unknown>;
    };
    expect(event.eventType).toBe('llm.request');
    expect(event.data).toMatchObject({
      taskId: 'task-1',
      outcome: 'SUCCESS',
      provider: 'ollama',
      model: 'qwen3.5:9b',
      promptTokens: 40,
      completionTokens: 12,
      totalTokens: 52,
      promptSha256: expect.stringMatching(/^[0-9a-f]{64}$/) as unknown,
    });
    const serialized = JSON.stringify(audit.record.mock.calls);
    expect(serialized).not.toContain('Summarise incident');
    expect(serialized).not.toContain('alice@contoso');
    expect(serialized).not.toContain('credential dumping');
  });

  it('does not hand out a completion the audit chain could not record', async () => {
    const { service, audit } = setup();
    audit.record.mockRejectedValue(new Error('db down'));
    await expectDeny(
      service.complete(AGENT, 'task-1', body()),
      503,
      'enforcement_dependency_unavailable',
    );
  });

  it('rejects streaming', async () => {
    const { service } = setup();
    await expect(
      service.complete(AGENT, 'task-1', { ...body(), stream: true }),
    ).rejects.toMatchObject({ status: 400 });
  });
});
