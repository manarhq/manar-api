import helmet from '@fastify/helmet';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { resolveCorsOrigin } from './cors';

/**
 * Phase 12a: `@fastify/helmet` registered on **both** Nest applications
 * (the human JWT surface and the mTLS agent surface) — security headers
 * (`X-Content-Type-Options`, `X-Frame-Options`, a restrictive default CSP,
 * etc.) are reasonable defense-in-depth on any HTTP surface, not just a
 * browser-facing one. `contentSecurityPolicy` is tightened for this being
 * a JSON API, not a page-serving app (default-src 'none' — nothing here
 * ever serves HTML/JS/CSS that a CSP would need to permit) except where
 * the Swagger UI is mounted (dev-only, `setupOpenApiDocs` — CSP is
 * relaxed there separately, see that function's own doc comment).
 */
export function setupHelmet(app: NestFastifyApplication): void {
  void app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    // This is an API, never an iframe target.
    frameguard: { action: 'deny' },
  });
}

/**
 * Section 99's hard CORS rule (`resolveCorsOrigin`'s own doc comment) —
 * applied only to the human-facing JWT surface (`AppModule`). The mTLS
 * `/agent/v1/*` surface has no browser CORS concept at all: it's called by
 * agent SDKs presenting a client certificate, never by a browser's
 * same-origin-policy-governed `fetch`, so enabling CORS there would be
 * meaningless — and Node's own `https` listener already rejects any
 * connection without a valid client certificate before Nest's routing (let
 * alone CORS) ever runs.
 */
export function setupCors(
  app: NestFastifyApplication,
  configService: ConfigService<AppConfig, true>,
): void {
  app.enableCors({
    origin: resolveCorsOrigin({
      CORS_ALLOWED_ORIGINS: configService.get('CORS_ALLOWED_ORIGINS', {
        infer: true,
      }),
      NODE_ENV: configService.get('NODE_ENV', { infer: true }),
    }),
    credentials: true,
  });
}
