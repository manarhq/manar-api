import {
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import type { AuthContext } from '../auth/auth-context';
import { AiJobStore, viewJob, type AiJobState } from '../ai-jobs/ai-job.store';
import { UsageMeterService } from '../billing/usage-meter.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TemporalClientService } from '../temporal/temporal-client.service';
import { PolicySuggestWorkflow } from '../temporal/workflows/policy-suggest.workflow';
import { PolicyService } from './policy.service';
import { SuggestPolicyRequestSchema } from './policy.validation';

/** Starts, reads and stops Suggest Policy background jobs (decision 6). */
@Injectable()
export class PolicySuggestJobsService {
  constructor(
    private readonly jobs: AiJobStore,
    private readonly temporal: TemporalClientService,
    private readonly meter: UsageMeterService,
    private readonly policies: PolicyService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  async start(auth: AuthContext, body: unknown): Promise<AiJobState> {
    const input = parseBodyOrThrow(SuggestPolicyRequestSchema, body);
    // An unknown policy is a 404 now, not after minutes of model time.
    if (input.policyId !== undefined) {
      const client = await this.tenants.getClient(auth.tenant.id);
      await this.policies.getPolicyOrThrow(client, input.policyId).catch(() => {
        throw new NotFoundException(`Policy "${input.policyId}" not found`);
      });
    }
    const job = await this.jobs.create(
      auth.tenant.id,
      auth.user.id,
      JSON.stringify(input),
    );
    // One AI action (paid extra), spent now and given back by the worker if nothing is produced.
    // A refusal (402 paused, 503 metering) surfaces here, before any work starts.
    try {
      await this.meter.consume(auth.tenant.id, 'ai', job.meterKey);
    } catch (error) {
      await this.jobs.update(auth.tenant.id, job.id, {
        status: 'failed',
        phase: 'done',
        error: 'not_started',
      });
      throw error;
    }
    try {
      await this.temporal.workflow.start(PolicySuggestWorkflow, {
        workflowId: `policy-suggest-${job.id}`,
        taskQueue: this.temporal.taskQueue,
        args: [{ tenantId: auth.tenant.id, jobId: job.id }],
      });
    } catch {
      await this.meter.release(auth.tenant.id, job.meterKey);
      await this.jobs.update(auth.tenant.id, job.id, {
        status: 'failed',
        phase: 'done',
        error: 'not_started',
      });
      throw new HttpException(
        { reason: 'ai_jobs_unavailable' },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
    return job;
  }

  /** The caller's own job. Someone else's, another workspace's or an unknown one are the same 404. */
  async read(auth: AuthContext, jobId: string): Promise<AiJobState> {
    const job = await this.jobs.get(auth.tenant.id, jobId);
    if (!job || job.userId !== auth.user.id) throw new NotFoundException();
    const seen = viewJob(job);
    if (seen.error === 'stalled' && job.status !== 'failed') {
      // The worker went away: finish the job and give the AI action back.
      await this.jobs.update(auth.tenant.id, jobId, {
        status: 'failed',
        phase: 'done',
        error: 'stalled',
      });
      await this.meter.release(auth.tenant.id, job.meterKey);
    }
    return seen;
  }

  async cancel(auth: AuthContext, jobId: string): Promise<AiJobState> {
    const job = await this.read(auth, jobId);
    if (['ready', 'failed', 'cancelled'].includes(job.status)) return job;
    const next = await this.jobs.update(auth.tenant.id, jobId, {
      cancelRequested: true,
    });
    return next ?? job;
  }
}
