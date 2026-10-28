import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { redisClientOptions } from '../audit/live/redis.config';
import { BoundedRedis } from '../common/redis/bounded-redis';

/** A lease record outlives a crashed host this long; after it the block counts as spent. */
const LEASE_TTL_MS = 24 * 60 * 60 * 1000;
const ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** Idempotent per lease id; a missing budget grants nothing. */
const LEASE_SCRIPT = `
local remaining = tonumber(redis.call("GET", KEYS[1]))
if remaining == nil then return 0 end
local existing = redis.call("GET", KEYS[2])
if existing then return tonumber(existing) end
local grant = math.min(tonumber(ARGV[1]), remaining)
if grant <= 0 then return 0 end
redis.call("DECRBY", KEYS[1], grant)
redis.call("SET", KEYS[2], grant, "PX", ARGV[2])
return grant
`;

/** The lease record is deleted in the same step, so a second release returns nothing. */
const RELEASE_SCRIPT = `
local granted = tonumber(redis.call("GET", KEYS[2]))
if granted == nil then return 0 end
redis.call("DEL", KEYS[2])
local back = math.min(tonumber(ARGV[1]), granted)
if back > 0 then redis.call("INCRBY", KEYS[1], back) end
return back
`;

/**
 * Spec 7.3: LLM token budgets are leased. A host takes a block (for example 50,000 tokens) and
 * comes back only when it is spent, so the budget is touched once per block, not once per call.
 * Server side only: the budget and its leases live in Valkey, every key carries the tenant, and
 * each step is one atomic script. Unreleased leases count as spent (a crashed host may have used
 * them), so the budget is never over-granted. Hub -> member -> host hierarchy and the host side
 * are not here (docs/decision-path.md, deferred). Any Valkey failure rejects: the caller denies.
 */
@Injectable()
export class TokenLeaseService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TokenLeaseService.name);
  private readonly redis: BoundedRedis;

  constructor(config: ConfigService<AppConfig, true>) {
    this.redis = new BoundedRedis(
      redisClientOptions((key) => config.get(key, { infer: true })),
      config.get('REDIS_TIMEOUT_MS', { infer: true }),
      this.logger,
      'Token lease',
    );
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.redis.connect();
    } catch (error) {
      this.logger.warn(
        `Could not connect to Valkey at startup (retries on first use): ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  onModuleDestroy(): Promise<void> {
    return this.redis.close();
  }

  async setBudget(
    tenantId: string,
    budget: string,
    tokens: number,
  ): Promise<void> {
    check(tenantId, budget);
    positiveOrZero(tokens);
    await (await this.redis.get()).set(remainingKey(tenantId, budget), tokens);
  }

  async remaining(tenantId: string, budget: string): Promise<number> {
    check(tenantId, budget);
    const v = await (
      await this.redis.get()
    ).get(remainingKey(tenantId, budget));
    return v === null ? 0 : Number(v);
  }

  /** Tokens granted, at most `block`, 0 when the budget is empty or unset. */
  async lease(
    tenantId: string,
    budget: string,
    leaseId: string,
    block: number,
  ): Promise<number> {
    check(tenantId, budget, leaseId);
    if (!Number.isInteger(block) || block <= 0) {
      throw new Error('block must be a positive integer');
    }
    const client = await this.redis.get();
    return Number(
      await client.eval(LEASE_SCRIPT, {
        keys: [
          remainingKey(tenantId, budget),
          leaseKey(tenantId, budget, leaseId),
        ],
        arguments: [String(block), String(LEASE_TTL_MS)],
      }),
    );
  }

  /** Tokens returned to the budget: the unspent part, at most what was granted, once. */
  async release(
    tenantId: string,
    budget: string,
    leaseId: string,
    unspent: number,
  ): Promise<number> {
    check(tenantId, budget, leaseId);
    positiveOrZero(unspent);
    const client = await this.redis.get();
    return Number(
      await client.eval(RELEASE_SCRIPT, {
        keys: [
          remainingKey(tenantId, budget),
          leaseKey(tenantId, budget, leaseId),
        ],
        arguments: [String(unspent)],
      }),
    );
  }
}

// The braces are a hash tag: a budget and its leases land in one slot.
const base = (tenantId: string, budget: string) =>
  `manar:lease:{${tenantId}|${budget}}`;
const remainingKey = (t: string, b: string) => `${base(t, b)}:remaining`;
const leaseKey = (t: string, b: string, l: string) => `${base(t, b)}:l:${l}`;

function check(...ids: string[]): void {
  for (const id of ids) {
    if (!ID.test(id)) throw new Error('invalid id');
  }
}

function positiveOrZero(n: number): void {
  if (!Number.isInteger(n) || n < 0) throw new Error('invalid token count');
}
