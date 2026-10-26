import {
  Body,
  CanActivate,
  Controller,
  ExecutionContext,
  Get,
  HttpCode,
  Injectable,
  NotFoundException,
  Post,
  Query,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiExcludeController } from '@nestjs/swagger';
import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { AppConfig } from '../config/env.validation';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { EdgePeerService, type EgressEvent } from './edge-peer.service';

/** The contract's hold: the gateway's request returns within this when nothing changes. */
export const EDGE_LONG_POLL_MS = 25_000;

const digest = (value: string) => createHash('sha256').update(value).digest();

/**
 * Headers an ingress, proxy or CDN adds; the gateway calls the pod directly and sends none. A
 * defence in depth only: the controls are the token and the NetworkPolicy.
 */
const PROXY_HEADERS = [
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'forwarded',
  'x-real-ip',
  'via',
  'cf-connecting-ip',
  'true-client-ip',
];

/**
 * 404, as if the routes did not exist, while the edge is off or when the request carries a
 * forwarding header (it came through an ingress, so a public route was misconfigured; a leaked
 * token is not enough). Otherwise bearer `MANAR_EDGE_GATEWAY_TOKEN`, compared in constant time
 * (both sides hashed first, so the length leaks nothing either), 401 without detail.
 */
@Injectable()
export class EdgeGatewayGuard implements CanActivate {
  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  canActivate(context: ExecutionContext): boolean {
    if (this.config.get('MANAR_EDGE_ENABLED', { infer: true }) !== 'true')
      throw new NotFoundException();
    const { headers } = context.switchToHttp().getRequest<FastifyRequest>();
    if (PROXY_HEADERS.some((name) => headers[name] !== undefined))
      throw new NotFoundException();
    const expected = this.config.get('MANAR_EDGE_GATEWAY_TOKEN', {
      infer: true,
    });
    const match = /^Bearer (.+)$/.exec(headers.authorization ?? '');
    if (
      !expected ||
      !match ||
      !timingSafeEqual(digest(match[1] ?? ''), digest(expected))
    )
      throw new UnauthorizedException();
    return true;
  }
}

/** A hostname or address literal as the gateway saw it in CONNECT; never a path or payload. */
const EVENT_HOST = /^[a-z0-9.:[\]_*-]{1,253}$/;

const EgressEventSchema = z.object({
  peerId: z.uuid(),
  at: z.iso.datetime({ offset: true }),
  host: z
    .string()
    .transform((h) => h.toLowerCase())
    .pipe(z.string().regex(EVENT_HOST)),
  port: z.number().int().min(1).max(65535),
  decision: z.enum(['allowed', 'denied']),
  /** Open set: `allowed`, `host_not_allowed`, `sni_mismatch`, `private_address`, `peer_cut`, ... */
  reason: z.string().regex(/^[a-z_]{1,40}$/),
  bytesUp: z.number().int().min(0),
  bytesDown: z.number().int().min(0),
  durationMs: z.number().int().min(0),
  /** The TLS ClientHello carried encrypted_client_hello. Optional. */
  ech: z.boolean().optional(),
});

const EgressBatchSchema = z.object({
  /** Optional UUID (the gateway sends a v4 per batch); a retried batch with the same id is recorded once. */
  batchId: z.uuid().optional(),
  events: z.array(z.unknown()).max(500),
});

/**
 * The gateway sync API (docs/edge.md section 2). Mounted only in `AppModule` (the HTTP port);
 * `AgentMtlsAppModule` never imports `EdgeHttpModule`, so nothing under `/internal` exists on the
 * agent mTLS listener (test/edge.e2e-spec.ts proves it). The NetworkPolicy admits only the gateway
 * pod to the HTTP port from outside manar-prod.
 */
@ApiExcludeController()
@Controller('internal/v1/edge')
@UseGuards(EdgeGatewayGuard)
export class EdgeInternalController {
  constructor(private readonly peers: EdgePeerService) {}

  @Get('peers')
  peersSince(@Query('after') after?: string) {
    const parsed = /^[0-9]{1,15}$/.test(after ?? '') ? Number(after) : 0;
    return this.peers.poll(parsed, EDGE_LONG_POLL_MS);
  }

  @Post('events')
  @HttpCode(200)
  async events(@Body() body: unknown) {
    const batch = parseBodyOrThrow(EgressBatchSchema, body);
    const valid: EgressEvent[] = [];
    let invalid = 0;
    for (const raw of batch.events) {
      const parsed = EgressEventSchema.safeParse(raw);
      if (parsed.success) valid.push(parsed.data);
      else invalid++;
    }
    const result = await this.peers.recordEgress(valid, batch.batchId);
    return { ...result, skipped: result.skipped + invalid };
  }
}
