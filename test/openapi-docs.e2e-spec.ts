import 'dotenv/config';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { ConfigService } from '@nestjs/config';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import type { AppConfig } from '../src/config/env.validation';
import {
  OPENAPI_DOCS_PATH,
  OPENAPI_JSON_PATH,
  setupOpenApiDocs,
} from '../src/openapi/setup-openapi-docs';

/**
 * Every path this phase decorated with `@nestjs/swagger` — the *complete*
 * human-facing (JWT-guarded) surface documented in Phase 11a Part 1's
 * design spec. Deliberately excludes routes that legitimately live on
 * this same human-facing Fastify app but were never in scope for
 * decoration: `GET /`, `GET /health/live`, `GET /health/ready` (public,
 * no JWT), and `POST /agents/enroll` (agent-facing — authenticated by a
 * one-time enrollment token, not a JWT — see `AgentEnrollController`'s
 * own doc comment for why it lives on this listener rather than the mTLS
 * one despite being agent-facing).
 */
const DOCUMENTED_PATHS = [
  '/agents',
  '/agents/{id}/enrollment-tokens',
  '/agents/{id}/revoke',
  '/tasks',
  '/tasks/{id}/revoke',
  '/policies',
  '/policies/{id}',
  '/policies/{id}/versions',
  '/policies/{id}/versions/{versionId}',
  '/policies/{id}/versions/{versionId}/publish',
  '/approvals',
  '/approvals/{id}/decide',
  '/approvals/{id}/handover',
  '/audit',
  '/audit/verify',
  '/kill-switches',
  '/tools',
  '/events/live',
  '/evidence/export',
  '/users',
  '/users/{id}',
  '/users/{id}/role-bindings',
  '/users/{id}/role-bindings/{role}',
  '/tenant/settings',
];

/**
 * Phase 11a Part 1's drift-check (Section 8): a basic sanity test against
 * the *live*, generated OpenAPI JSON document — not a hand-maintained
 * fixture — so it actually catches drift between what's decorated and
 * what's real (a controller added later without `@nestjs/swagger`
 * decorators, a path that silently disappears, the mTLS surface leaking
 * in). This is what Phase 11b (`manar-web`)'s codegen step is meant to
 * detect regressions against; this test is `manar-api`'s own half of that
 * contract.
 *
 * Builds `AppModule` exactly like `test/app.e2e-spec.ts` does (a real
 * Nest app, real infra — `pnpm infra:up` — same as the rest of this e2e
 * suite), then calls the *exact* `setupOpenApiDocs` function `main.ts`'s
 * real bootstrap calls, rather than re-deriving the document some other
 * way.
 */
describe('OpenAPI document (e2e)', () => {
  let app: NestFastifyApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );

    const configService = app.get(ConfigService<AppConfig, true>);
    setupOpenApiDocs(app, configService);

    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('serves the Swagger UI at /api/v1/docs', async () => {
    const response = await request(app.getHttpServer()).get(
      `/${OPENAPI_DOCS_PATH}`,
    );
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('text/html');
  });

  it('serves a well-formed OpenAPI 3.x document at /api/v1/docs-json', async () => {
    const response = await request(app.getHttpServer()).get(
      `/${OPENAPI_JSON_PATH}`,
    );
    expect(response.status).toBe(200);

    const document = response.body as {
      openapi: string;
      info: { title: string; version: string };
      paths: Record<string, Record<string, unknown>>;
      tags?: { name: string }[];
    };

    expect(document.openapi).toMatch(/^3\./);
    expect(document.info.title).toBeTruthy();
    expect(document.info.version).toBeTruthy();
    expect(document.paths).toBeTruthy();
    expect(Object.keys(document.paths).length).toBeGreaterThan(0);
  });

  it('includes every human-facing controller documented in Phase 11a Part 1', async () => {
    const response = await request(app.getHttpServer()).get(
      `/${OPENAPI_JSON_PATH}`,
    );
    const document = response.body as {
      paths: Record<string, Record<string, { tags?: string[] }>>;
    };

    // `@nestjs/swagger` never auto-populates a top-level `document.tags`
    // array from each controller's `@ApiTags()` (that only happens via an
    // explicit `DocumentBuilder.addTag()` call, which this app doesn't
    // make) — the real signal is each *operation's own* `tags` array, so
    // collect those instead of asserting on `document.tags`.
    const tagNames = new Set(
      Object.values(document.paths).flatMap((methods) =>
        Object.values(methods).flatMap((operation) => operation.tags ?? []),
      ),
    );
    for (const expectedTag of [
      'agents',
      'tasks',
      'policies',
      'approvals',
      'audit',
      'events',
      'evidence',
    ]) {
      expect(
        tagNames.has(expectedTag),
        `missing @ApiTags("${expectedTag}")`,
      ).toBe(true);
    }

    const paths = Object.keys(document.paths);
    for (const expectedPath of DOCUMENTED_PATHS) {
      expect(paths, `missing documented path "${expectedPath}"`).toContain(
        expectedPath,
      );
    }
  });

  it('never documents the mTLS agent-facing /agent/v1/* surface', async () => {
    const response = await request(app.getHttpServer()).get(
      `/${OPENAPI_JSON_PATH}`,
    );
    const document = response.body as {
      paths: Record<string, Record<string, unknown>>;
    };

    // The entire mTLS surface (POST /agent/v1/authorize,
    // GET /agent/v1/approvals/:id, POST /agent/v1/tasks/:id/delegate,
    // POST /agent/v1/tools/invoke) is served by a wholly separate Nest
    // application (AgentMtlsAppModule) that this document's app never
    // mounts — so no `/agent/v1/*` path should ever appear here at all.
    const agentPaths = Object.keys(document.paths).filter((path) =>
      path.startsWith('/agent/v1'),
    );
    expect(agentPaths).toEqual([]);
  });

  it('every documented human-facing path requires bearer auth', async () => {
    const response = await request(app.getHttpServer()).get(
      `/${OPENAPI_JSON_PATH}`,
    );
    const document = response.body as {
      paths: Record<
        string,
        Record<string, { security?: { jwt?: string[] }[] }>
      >;
    };

    for (const path of DOCUMENTED_PATHS) {
      const methods = document.paths[path];
      expect(methods, `document is missing path "${path}"`).toBeTruthy();
      if (!methods) continue;

      for (const [method, operation] of Object.entries(methods)) {
        const hasBearerAuth = (operation.security ?? []).some(
          (requirement) => 'jwt' in requirement,
        );
        expect(
          hasBearerAuth,
          `${method.toUpperCase()} ${path} is missing bearer auth in its OpenAPI security requirement`,
        ).toBe(true);
      }
    }
  });
});
