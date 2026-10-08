import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import type { AppConfig } from '../config/env.validation';

/** Where the Swagger UI is mounted — also the base the raw JSON document's default `-json` suffix is computed from (see `setupOpenApiDocs`'s own doc comment). Exported so `main.ts` and any test that wants to hit the live document (e.g. `test/openapi-docs.e2e-spec.ts`) share one source of truth for the path instead of duplicating the literal. */
export const OPENAPI_DOCS_PATH = 'api/v1/docs';

/** `SwaggerModule.setup`'s default (no `jsonDocumentUrl` override): `<path>-json`. */
export const OPENAPI_JSON_PATH = `${OPENAPI_DOCS_PATH}-json`;

/**
 * Phase 11a Part 1 (Section 8) — the human-facing OpenAPI surface. Must
 * only ever be called on the JWT-guarded human `app` (see `main.ts`'s
 * bootstrap), never on `agentMtlsApp`: the two are wholly separate Nest
 * applications (`AgentMtlsAppModule`'s own doc comment), so simply never
 * calling this on the mTLS app is what keeps `/agent/v1/*` out of this
 * document entirely — no per-controller `@ApiExcludeController()` needed.
 *
 * Dev-only: gated on `NODE_ENV !== 'production'` via this app's own typed
 * `ConfigService` (never a raw `process.env.NODE_ENV` read), matching
 * Section 8's "Swagger UI, dev-only" requirement.
 * `SwaggerModule.setup`'s default (no `jsonDocumentUrl` override) serves
 * the raw JSON document at `<path>-json` — `OPENAPI_JSON_PATH` above —
 * which is exactly the stable path `manar-web`'s codegen step is meant to
 * fetch.
 *
 * Extracted out of `main.ts` (rather than inlined in `bootstrap()`) so
 * `test/openapi-docs.e2e-spec.ts` (the Section 8 drift-check test) can call
 * the exact same setup a real boot performs, against an in-process
 * `TestingModule`-built app, without duplicating this logic.
 */
export function setupOpenApiDocs(
  app: NestFastifyApplication,
  configService: ConfigService<AppConfig, true>,
): void {
  if (configService.get('NODE_ENV', { infer: true }) === 'production') {
    return;
  }

  const swaggerConfig = new DocumentBuilder()
    .setTitle('Manar API')
    .setDescription(
      'Human-facing (JWT-guarded) control-plane API for Manar. Does not ' +
        'include the mTLS agent-facing `/agent/v1/*` surface, which is a ' +
        'different consumer (the agent SDKs) served by a separate Nest ' +
        'application and never mounted here.',
    )
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description:
          "A Keycloak-issued human access token, verified by this tenant realm's JWKS (see docs/human-auth.md).",
      },
      'jwt',
    )
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description:
          'A client-credentials token from the platform realm for manar-fleet (ADR-0010). Only /platform/v1/*.',
      },
      'platform',
    )
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup(OPENAPI_DOCS_PATH, app, document);
}
