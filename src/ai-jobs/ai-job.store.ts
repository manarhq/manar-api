import { randomUUID } from 'node:crypto';
import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { redisClientOptions } from '../audit/live/redis.config';
import { BoundedRedis } from '../common/redis/bounded-redis';
import type { AppConfig } from '../config/env.validation';

export type AiJobStatus =
  'queued' | 'running' | 'ready' | 'failed' | 'cancelled';
export type AiJobPhase = 'queued' | 'drafting' | 'saving' | 'done';

export interface AiJobResult {
  available: boolean;
  policyId: string | null;
  versionId: string | null;
  explanation: string | null;
  confidence: number | null;
  ruleCount: number;
}

/** Everything a person watching a background AI job needs. No prompt: that lives apart, briefly. */
export interface AiJobState {
  id: string;
  tenantId: string;
  /** Only this person may read or cancel the job. */
  userId: string;
  kind: 'policy_suggest';
  status: AiJobStatus;
  phase: AiJobPhase;
  /** Estimated from the characters written so far (4 per token). */
  outputTokens: number;
  createdAt: string;
  updatedAt: string;
  /** The metering key of the AI action this job spent; released when nothing was produced. */
  meterKey: string;
  cancelRequested: boolean;
  result?: AiJobResult;
  /** A fixed code, never a message: `model_unavailable`, `internal`, `stalled`. */
  error?: string;
}

const JOB_TTL_MS = 24 * 60 * 60 * 1000;
/** The prompt waits for the worker; it is deleted the moment the worker has it. */
const INPUT_TTL_MS = 60 * 60 * 1000;
/** A running job that wrote nothing for this long has lost its worker. */
export const STALLED_AFTER_MS = 90_000;

const stateKey = (tenantId: string, id: string) =>
  `manar:aijob:${tenantId}:${id}`;
const inputKey = (tenantId: string, id: string) =>
  `manar:aijob-input:${tenantId}:${id}`;

/**
 * Background AI jobs' state in Valkey/Redis, for 24 hours (performance program, decision 6). Every
 * key carries the tenant id and every read takes it, so one workspace can never read another's
 * job. The API reads it for the console; the worker writes it. The durable result of a policy job
 * is the DRAFT version it created, not this record.
 */
@Injectable()
export class AiJobStore implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AiJobStore.name);
  private readonly redis: BoundedRedis;

  constructor(configService: ConfigService<AppConfig, true>) {
    this.redis = new BoundedRedis(
      redisClientOptions((key) => configService.get(key, { infer: true })),
      configService.get('REDIS_TIMEOUT_MS', { infer: true }),
      this.logger,
      'AI job store',
    );
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.redis.connect();
    } catch (error) {
      this.logger.warn(
        `Could not connect to Redis at startup (will retry on first use): ${error instanceof Error ? error.message : 'error'}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis.close();
  }

  async create(
    tenantId: string,
    userId: string,
    input: string,
    now = new Date(),
  ): Promise<AiJobState> {
    const id = randomUUID();
    const state: AiJobState = {
      id,
      tenantId,
      userId,
      kind: 'policy_suggest',
      status: 'queued',
      phase: 'queued',
      outputTokens: 0,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      meterKey: `ai:job:${id}`,
      cancelRequested: false,
    };
    const client = await this.redis.get();
    await client.set(stateKey(tenantId, id), JSON.stringify(state), {
      PX: JOB_TTL_MS,
    });
    await client.set(inputKey(tenantId, id), input, { PX: INPUT_TTL_MS });
    return state;
  }

  /** The job, only if `tenantId` owns it. */
  async get(tenantId: string, id: string): Promise<AiJobState | undefined> {
    const client = await this.redis.get();
    const raw = await client.get(stateKey(tenantId, id));
    return raw ? (JSON.parse(raw) as AiJobState) : undefined;
  }

  async update(
    tenantId: string,
    id: string,
    patch: Partial<Omit<AiJobState, 'id' | 'tenantId' | 'userId'>>,
    now = new Date(),
  ): Promise<AiJobState | undefined> {
    const current = await this.get(tenantId, id);
    if (!current) return undefined;
    // Never undo a terminal state or a cancel request by a late progress write.
    const locked = ['ready', 'failed', 'cancelled'].includes(current.status);
    const next: AiJobState = {
      ...current,
      ...(locked ? {} : patch),
      cancelRequested: current.cancelRequested || !!patch.cancelRequested,
      updatedAt: now.toISOString(),
    };
    const client = await this.redis.get();
    await client.set(stateKey(tenantId, id), JSON.stringify(next), {
      PX: JOB_TTL_MS,
    });
    return next;
  }

  /** Reads the prompt once and deletes it. */
  async takeInput(tenantId: string, id: string): Promise<string | undefined> {
    const client = await this.redis.get();
    const key = inputKey(tenantId, id);
    const raw = await client.get(key);
    await client.del(key);
    return raw ?? undefined;
  }
}

/** `running` with no write for `STALLED_AFTER_MS` is a job that lost its worker: say so. */
export function viewJob(job: AiJobState, now = new Date()): AiJobState {
  const silent = now.getTime() - Date.parse(job.updatedAt);
  return (job.status === 'running' || job.status === 'queued') &&
    silent > STALLED_AFTER_MS
    ? { ...job, status: 'failed', error: 'stalled' }
    : job;
}
