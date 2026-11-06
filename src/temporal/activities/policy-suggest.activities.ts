import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AiAdvisoryClient } from '../../ai-advisory/ai-advisory-client.service';
import { AiJobStore, type AiJobResult } from '../../ai-jobs/ai-job.store';
import { UsageMeterService } from '../../billing/usage-meter.service';
import type { AppConfig } from '../../config/env.validation';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { PolicyService } from '../../policy/policy.service';
import {
  SuggestPolicyRequestSchema,
  type SuggestPolicyRequest,
} from '../../policy/policy.validation';
import type {
  PolicySuggestActivities,
  PolicySuggestJobInput,
} from './policy-suggest-activities.interface';

/** Progress is written at most this often, and a quiet model still refreshes the job this often. */
const PROGRESS_MS = 1000;
const HEARTBEAT_MS = 10_000;

/**
 * The real implementation behind `PolicySuggestActivities`, in the worker only. Streams the draft
 * from manar-ai, writes progress for the console, creates the DRAFT `PolicyVersion` (never
 * published) and gives the AI action back when nothing was produced. No prompt, answer or token
 * text is logged: counts and fixed codes only.
 */
@Injectable()
export class PolicySuggestActivitiesFactory {
  private readonly logger = new Logger(PolicySuggestActivitiesFactory.name);

  constructor(
    private readonly jobs: AiJobStore,
    private readonly advisory: AiAdvisoryClient,
    private readonly policies: PolicyService,
    private readonly tenants: TenantDatabaseManager,
    private readonly meter: UsageMeterService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  build(): PolicySuggestActivities {
    return {
      runPolicySuggestionJob: (input) => this.run(input),
    };
  }

  private async run({ tenantId, jobId }: PolicySuggestJobInput): Promise<void> {
    const job = await this.jobs.get(tenantId, jobId);
    if (!job) return;
    let chars = 0;
    const finish = async (
      status: 'ready' | 'failed' | 'cancelled',
      extra: { result?: AiJobResult; error?: string } = {},
    ): Promise<void> => {
      await this.jobs.update(tenantId, jobId, {
        status,
        phase: 'done',
        ...extra,
      });
      // Nothing produced: the AI action is given back.
      if (!extra.result?.available)
        await this.meter.release(tenantId, job.meterKey);
    };
    if (job.cancelRequested) return finish('cancelled');

    const raw = await this.jobs.takeInput(tenantId, jobId);
    let input: SuggestPolicyRequest;
    try {
      input = SuggestPolicyRequestSchema.parse(JSON.parse(raw ?? 'null'));
    } catch {
      return finish('failed', { error: 'internal' });
    }

    await this.jobs.update(tenantId, jobId, {
      status: 'running',
      phase: 'drafting',
    });
    const abort = new AbortController();
    let lastWrite = 0;
    const tick = async (): Promise<void> => {
      const now = await this.jobs.update(tenantId, jobId, {
        outputTokens: Math.ceil(chars / 4),
      });
      if (now?.cancelRequested) abort.abort();
    };
    const beat = setInterval(
      () => void tick().catch(() => undefined),
      HEARTBEAT_MS,
    );
    try {
      const draft = await this.advisory.suggestPolicyStream(
        {
          naturalLanguageDescription: input.naturalLanguageDescription,
          tenantId,
        },
        {
          signal: abort.signal,
          deadlineMs: Number(
            this.config.get('AI_JOB_TIMEOUT_MS', { infer: true }),
          ),
          onProgress: (characters) => {
            chars = characters;
            if (Date.now() - lastWrite >= PROGRESS_MS) {
              lastWrite = Date.now();
              void tick().catch(() => undefined);
            }
          },
        },
      );
      if (abort.signal.aborted) return await finish('cancelled');

      await this.jobs.update(tenantId, jobId, {
        phase: 'saving',
        outputTokens: Math.ceil(chars / 4),
      });
      const tenantClient = await this.tenants.getClient(tenantId);
      const saved = await this.policies.persistSuggestion(
        tenantClient,
        { ...input, authorId: job.userId },
        draft,
      );
      const result: AiJobResult = {
        available: saved.available,
        policyId: saved.policyId,
        versionId: saved.version?.id ?? null,
        explanation: saved.explanation,
        confidence: saved.confidence,
        ruleCount: draft?.rules.length ?? 0,
      };
      await finish('ready', {
        result,
        ...(saved.available ? {} : { error: 'model_unavailable' }),
      });
    } catch (error) {
      this.logger.warn(
        `Policy suggestion job ${jobId} failed: ${error instanceof Error ? error.name : 'error'}`,
      );
      await finish('failed', { error: 'internal' }).catch(() => undefined);
    } finally {
      clearInterval(beat);
    }
  }
}
