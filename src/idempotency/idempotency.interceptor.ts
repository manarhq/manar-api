import {
  CallHandler,
  ConflictException,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { createHash } from 'node:crypto';
import { ConfigService } from '@nestjs/config';
import type { FastifyRequest } from 'fastify';
import { firstValueFrom, Observable, of } from 'rxjs';
import type { AppConfig } from '../config/env.validation';
import { IdempotencyStoreService } from './idempotency-store.service';
import { failClosed } from '../common/fail-closed/fail-closed';

interface RequestWithOptionalContexts extends FastifyRequest {
  authContext?: { tenant?: { id?: string }; user?: { id?: string } };
  agentContext?: { agent?: { id?: string } };
}

/**
 * Phase 12a (Section 8). Applied per-route (`@UseInterceptors(IdempotencyInterceptor)`)
 * to the specific mutation endpoints that genuinely need it — not
 * blanket-applied globally (see `docs/security.md`'s idempotency section
 * for exactly which endpoints and why: agent creation, policy publish,
 * kill-switch activation, webhook registration; deliberately NOT grant
 * redemption, which Phase 8 already made single-use by its own, different
 * mechanism).
 *
 * Opt-in via the `Idempotency-Key` request header: a request with no such
 * header is completely unaffected (`next.handle()` untouched) — this
 * interceptor never *requires* the header, only honors it when present.
 *
 * With a key present:
 *   1. Atomically claim `<tenant-or-agent>:<controller>.<handler>:<key>`
 *      (`IdempotencyStoreService.claim`, a Redis `SET NX`).
 *   2. **Claim succeeded** (first time this key has been seen): run the
 *      real handler, then cache its resolved value for
 *      `IDEMPOTENCY_KEY_TTL_MS` — a replay with the same key inside that
 *      window returns this cached value without re-executing the handler
 *      at all (no second `Agent`/`PolicyVersion`/`WebhookEndpoint` row, no
 *      second kill-switch `AuditEvent`). A handler that *throws* releases
 *      the claim instead of caching an error — a failed attempt must not
 *      permanently block a legitimate retry with the same key.
 *   3. **Claim failed** (key already in use): if a real response was
 *      already cached, return it directly. If not (the original request
 *      is still genuinely in flight), reject with 409 — a concurrent
 *      duplicate is a real conflict, not something safe to silently drop
 *      or block on.
 */
@Injectable()
export class IdempotencyInterceptor implements NestInterceptor {
  private readonly logger = new Logger(IdempotencyInterceptor.name);

  constructor(
    private readonly store: IdempotencyStoreService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<unknown>> {
    const request = context
      .switchToHttp()
      .getRequest<RequestWithOptionalContexts>();
    const header = request.headers['idempotency-key'];
    const idempotencyKey = Array.isArray(header) ? header[0] : header;

    if (!idempotencyKey) {
      return next.handle();
    }

    const scope =
      request.authContext?.tenant?.id ??
      request.agentContext?.agent?.id ??
      'anonymous';
    const routeKey = `${context.getClass().name}.${context.getHandler().name}`;
    // The key is only a replay of the same request: same caller, same route
    // target, same body. Reusing it for another target (a kill switch on a
    // different agent) runs that request instead of answering with the first.
    const fingerprint = createHash('sha256')
      .update(
        JSON.stringify([
          request.authContext?.user?.id ?? null,
          request.params ?? null,
          request.body ?? null,
        ]),
      )
      .digest('hex');
    const redisKey = `manar:idempotency:${scope}:${routeKey}:${idempotencyKey}:${fingerprint}`;
    const ttlMs = this.configService.get('IDEMPOTENCY_KEY_TTL_MS', {
      infer: true,
    });

    const inProgressTtlMs = this.configService.get(
      'IDEMPOTENCY_IN_PROGRESS_TTL_MS',
      { infer: true },
    );

    // Without the store replay protection cannot be given, so nothing
    // runs: 503 enforcement_dependency_unavailable, never a bare 500.
    const claimed = await failClosed('idempotency-store', () =>
      this.store.claim(redisKey, inProgressTtlMs),
    );
    if (!claimed) {
      const cached = await failClosed('idempotency-store', () =>
        this.store.getCached(redisKey),
      );
      if (cached !== undefined) {
        return of(cached);
      }
      throw new ConflictException(
        'A request with this Idempotency-Key is already in progress',
      );
    }

    let value: unknown;
    try {
      value = await firstValueFrom(next.handle(), { defaultValue: null });
    } catch (error) {
      try {
        await this.store.release(redisKey);
      } catch (releaseError) {
        // The marker expires after IDEMPOTENCY_IN_PROGRESS_TTL_MS; the
        // caller still gets the handler's own error.
        this.logger.warn(
          `Idempotency key not released (expires in ${inProgressTtlMs} ms): ${errorMessage(releaseError)}`,
        );
      }
      throw error;
    }

    // The change is committed: answer with it even if caching the result
    // fails. A retry then sees 409 until the in-progress marker expires.
    try {
      await this.store.store(redisKey, value, ttlMs);
    } catch (storeError) {
      this.logger.warn(
        `Idempotency result not cached (key expires in ${inProgressTtlMs} ms): ${errorMessage(storeError)}`,
      );
    }
    return of(value);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
