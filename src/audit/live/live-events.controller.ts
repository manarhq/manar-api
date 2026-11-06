import {
  BadRequestException,
  Controller,
  Get,
  Logger,
  Query,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiProduces,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../../auth/auth-context';
import type { AuthContext } from '../../auth/auth-context';
import { JwtAuthGuard } from '../../auth/jwt-auth.guard';
import { RequireRole } from '../../auth/require-role.decorator';
import { RolesGuard } from '../../auth/roles.guard';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { recordLiveStreamClosed } from '../../metrics/metrics';
import { RedisPubSubService } from './redis-pubsub.service';
import { LiveAuditEventEnvelopeDto } from './live-events.dto';

const HEARTBEAT_INTERVAL_MS = 25_000;
/** A client that reads slower than events arrive is cut off past this much unsent data. */
export const MAX_BUFFERED_BYTES = 1_048_576;
/**
 * Event-type prefixes a client may ask for (`?prefix=approval.`). A fixed list, not free text, so
 * the parameter can never become a probe or an unbounded filter. Add a prefix here when a new
 * event family needs a filtered stream.
 */
export const LIVE_EVENT_PREFIXES: readonly string[] = [
  'approval.',
  'authorization.',
  'task.',
  'agent.',
  'host.',
  'door.',
  'secret.',
  'billing.',
  'user.',
  'ai_system.',
];

/** The validated `prefix` query value, or undefined for the full feed. */
export function parseLivePrefix(raw: unknown): string | undefined {
  if (raw === undefined || raw === '') return undefined;
  if (typeof raw !== 'string' || !LIVE_EVENT_PREFIXES.includes(raw)) {
    throw new BadRequestException('invalid_prefix');
  }
  return raw;
}

/**
 * `GET /events/live` (Phase 9b, Section 62). JWT-guarded, human-facing
 * only (never exposed on the mTLS agent surface). It streams the same
 * audit events `GET /audit` serves, so it carries the same audit read
 * roles (Gate 0 finding S24: it used to stream to any authenticated
 * tenant user). A caller only ever receives events for `auth.tenant.id`,
 * resolved from the verified JWT — never a client-supplied tenant id.
 *
 * A Server-Sent Events stream: `AuditIndexerService` (the same Kafka
 * consumer that indexes into OpenSearch) publishes every new event to
 * `RedisPubSubService`'s per-tenant channel; this handler subscribes to
 * that channel for the lifetime of the HTTP connection and forwards each
 * message as an SSE `audit-event` frame. The Redis subscriber is shared by
 * the tenant's open streams (see `RedisPubSubService.subscribeTenant`) and
 * released when the client disconnects. `?prefix=approval.` filters on the
 * server; a stream that falls too far behind is closed (backpressure).
 */
@ApiTags('events')
@ApiBearerAuth('jwt')
@Controller('events')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class LiveEventsController {
  private readonly logger = new Logger(LiveEventsController.name);

  constructor(private readonly redisPubSubService: RedisPubSubService) {}

  @Get('live')
  @ApiOperation({
    summary: 'Live tenant-scoped audit event feed (Server-Sent Events)',
    description:
      'A long-lived text/event-stream connection: an initial `: connected` comment, then one `event: audit-event` frame per new tenant event (`data:` is a JSON-encoded DomainEventEnvelope), plus periodic `: heartbeat` comments. Requires AUDITOR, SECURITY_ADMIN, or TENANT_OWNER. This describes the stream shape only; standard HTTP client generators typically cannot consume SSE the same way as a normal JSON response.',
  })
  @ApiProduces('text/event-stream')
  @ApiResponse({
    status: 200,
    description:
      "text/event-stream — each `audit-event` frame's data is a LiveAuditEventEnvelopeDto.",
    type: LiveAuditEventEnvelopeDto,
  })
  @ApiQuery({
    name: 'prefix',
    required: false,
    description: `Only stream events whose type starts with this prefix. One of: ${LIVE_EVENT_PREFIXES.join(', ')}. Omit for every event.`,
  })
  async live(
    @CurrentAuth() auth: AuthContext,
    @Res() reply: FastifyReply,
    @Query('prefix') rawPrefix?: string,
  ): Promise<void> {
    const prefix = parseLivePrefix(rawPrefix);
    const raw = reply.raw;
    let live = false;
    let closed = false;

    const send = (frame: string): void => {
      if (!live || closed) return;
      raw.write(frame);
      // Backpressure: a stalled client must not make this process buffer without bound.
      if (raw.writableLength > MAX_BUFFERED_BYTES) {
        this.logger.warn(
          `Closing a live-feed connection for tenant "${auth.tenant.id}": ${raw.writableLength} bytes unsent`,
        );
        recordLiveStreamClosed('backpressure');
        raw.destroy();
      }
    };

    type Subscription = Awaited<
      ReturnType<RedisPubSubService['subscribeTenant']>
    >;
    let subscription: Subscription | undefined;
    let heartbeat: ReturnType<typeof setInterval> | undefined = undefined;
    const release = (): void => {
      subscription?.unsubscribe().catch((error: unknown) => {
        this.logger.warn(
          `Error unsubscribing a live-feed connection for tenant "${auth.tenant.id}": ${error instanceof Error ? error.message : String(error)}`,
        );
      });
    };
    const cleanup = (): void => {
      if (closed) return;
      closed = true;
      clearInterval(heartbeat);
      release();
    };
    // Registered first: a client that leaves while Redis is still being asked is not leaked.
    raw.on('close', cleanup);
    raw.on('error', cleanup);

    // Subscribe BEFORE answering 200: if Redis is down the client gets a 503 (and polls) instead
    // of a stream that looks healthy and never delivers.
    try {
      subscription = await this.redisPubSubService.subscribeTenant(
        auth.tenant.id,
        (envelope) => {
          if (prefix && !envelope.eventType.startsWith(prefix)) return;
          send(`event: audit-event\ndata: ${JSON.stringify(envelope)}\n\n`);
        },
      );
    } catch (error) {
      closed = true;
      return throwFailClosed('live_feed', error);
    }
    if (closed) {
      release();
      return;
    }

    heartbeat = setInterval(
      () => send(': heartbeat\n\n'),
      HEARTBEAT_INTERVAL_MS,
    );
    heartbeat.unref?.();

    raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      // Nginx/other reverse proxies: don't buffer an SSE stream.
      'X-Accel-Buffering': 'no',
    });
    raw.write(': connected\n\n');
    live = true;
  }
}
