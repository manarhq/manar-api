import { Controller, Get, Logger, Res, UseGuards } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { CurrentAuth } from '../../auth/auth-context';
import type { AuthContext } from '../../auth/auth-context';
import { JwtAuthGuard } from '../../auth/jwt-auth.guard';
import { RedisPubSubService } from './redis-pubsub.service';

const HEARTBEAT_INTERVAL_MS = 25_000;

/**
 * `GET /events/live` (Phase 9b, Section 62). JWT-guarded, human-facing
 * only (never exposed on the mTLS agent surface — same posture
 * `AuditController` already takes). Deliberately **no** `@RequireRole`
 * (unlike `/audit/verify`/`/evidence/export`, which explicitly restrict to
 * `AUDITOR`/`SECURITY_ADMIN`/`TENANT_OWNER`): the design spec describes
 * this endpoint only as "JWT-guarded, human-facing, tenant-scoped" — a
 * live activity dashboard is a reasonable thing for any authenticated
 * tenant user to watch, not an auditor-tier surface. Tenant scoping is
 * what actually matters here (Section 62's real invariant): a caller only
 * ever receives events for `auth.tenant.id`, resolved from the verified
 * JWT the same way every other authenticated endpoint does — never a
 * client-supplied tenant id.
 *
 * A Server-Sent Events stream: `AuditIndexerService` (the same Kafka
 * consumer that indexes into OpenSearch) publishes every new event to
 * `RedisPubSubService`'s per-tenant channel; this handler subscribes to
 * that channel for the lifetime of the HTTP connection and forwards each
 * message as an SSE `audit-event` frame, cleaning up its dedicated Redis
 * connection the moment the client disconnects.
 */
@Controller('events')
@UseGuards(JwtAuthGuard)
export class LiveEventsController {
  private readonly logger = new Logger(LiveEventsController.name);

  constructor(private readonly redisPubSubService: RedisPubSubService) {}

  @Get('live')
  async live(
    @CurrentAuth() auth: AuthContext,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      // Nginx/other reverse proxies: don't buffer an SSE stream.
      'X-Accel-Buffering': 'no',
    });
    reply.raw.write(': connected\n\n');

    const subscription = await this.redisPubSubService.subscribeTenant(
      auth.tenant.id,
      (envelope) => {
        reply.raw.write(
          `event: audit-event\ndata: ${JSON.stringify(envelope)}\n\n`,
        );
      },
    );

    const heartbeat = setInterval(() => {
      reply.raw.write(': heartbeat\n\n');
    }, HEARTBEAT_INTERVAL_MS);
    heartbeat.unref?.();

    const cleanup = (): void => {
      clearInterval(heartbeat);
      subscription.unsubscribe().catch((error: unknown) => {
        this.logger.warn(
          `Error unsubscribing a live-feed connection for tenant "${auth.tenant.id}": ${error instanceof Error ? error.message : String(error)}`,
        );
      });
    };
    reply.raw.on('close', cleanup);
    reply.raw.on('error', cleanup);
  }
}
