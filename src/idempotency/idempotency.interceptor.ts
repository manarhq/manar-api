import {
  CallHandler,
  ConflictException,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { FastifyRequest } from 'fastify';
import { firstValueFrom, Observable, of } from 'rxjs';
import type { AppConfig } from '../config/env.validation';
import { IdempotencyStoreService } from './idempotency-store.service';

interface RequestWithOptionalContexts extends FastifyRequest {
  authContext?: { tenant?: { id?: string } };
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
    const redisKey = `manar:idempotency:${scope}:${routeKey}:${idempotencyKey}`;
    const ttlMs = this.configService.get('IDEMPOTENCY_KEY_TTL_MS', {
      infer: true,
    });

    const claimed = await this.store.claim(redisKey, ttlMs);
    if (!claimed) {
      const cached = await this.store.getCached(redisKey);
      if (cached !== undefined) {
        return of(cached);
      }
      throw new ConflictException(
        'A request with this Idempotency-Key is already in progress',
      );
    }

    try {
      const value: unknown = await firstValueFrom(next.handle(), {
        defaultValue: null,
      });
      await this.store.store(redisKey, value, ttlMs);
      return of(value);
    } catch (error) {
      await this.store.release(redisKey);
      throw error;
    }
  }
}
