import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';

describe('AppModule (e2e)', () => {
  let app: NestFastifyApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterEach(async () => {
    await app.close();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer() as App)
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });

  it('/health/live (GET)', () => {
    return request(app.getHttpServer() as App)
      .get('/health/live')
      .expect(200)
      .expect({ status: 'ok' });
  });

  /**
   * Release 2026-11-11: `/health/ready` used to return a static
   * `{ status: 'ok' }` regardless of whether any dependency was reachable,
   * behind a stale comment claiming this phase had none. It now reports
   * per-dependency state.
   *
   * This test asserts the *contract*, not a fixed body, because the body
   * legitimately varies with what happens to be running: in CI every
   * dependency is attached, while a developer running only Postgres should
   * still see a truthful degraded report rather than a green light. What
   * must hold either way is that the endpoint distinguishes "ready" from
   * "healthy" — the whole point of the change is that optional-dependency
   * degradation yields `ready: true, status: 'degraded'` and never a
   * readiness failure, while a required dependency being down does gate
   * traffic.
   */
  it('/health/ready (GET) reports per-dependency readiness, not a static ok', async () => {
    const response = await request(app.getHttpServer()).get('/health/ready');

    // 200 when ready (possibly degraded), 503 when a required dependency
    // is down — both are correct answers, and both must carry the report.
    expect([200, 503]).toContain(response.status);

    const body = response.body as {
      status: string;
      ready: boolean;
      checkedAt: string;
      dependencies: Record<
        string,
        { status: string; required: boolean; impact: string }
      >;
    };

    expect(['ok', 'degraded', 'unhealthy']).toContain(body.status);
    expect(typeof body.ready).toBe('boolean');
    expect(body.ready).toBe(response.status === 200);
    expect(Number.isNaN(Date.parse(body.checkedAt))).toBe(false);

    // Every dependency states whether it gates traffic and what breaks
    // without it — an operator reading this must not have to guess.
    const dependencies = Object.entries(body.dependencies);
    expect(dependencies.length).toBeGreaterThan(0);
    for (const [name, dependency] of dependencies) {
      expect(
        ['ok', 'degraded', 'stale', 'unhealthy'],
        `${name}.status`,
      ).toContain(dependency.status);
      expect(typeof dependency.required, `${name}.required`).toBe('boolean');
      expect(dependency.impact.length, `${name}.impact`).toBeGreaterThan(0);
    }

    // The load-bearing invariant: an unhealthy OPTIONAL dependency must
    // never make the process un-ready. This is what stops the AI advisory
    // service — which is optional by design — from taking the API out of
    // rotation when it degrades.
    const unhealthyRequired = dependencies.filter(
      ([, dependency]) =>
        dependency.required && dependency.status === 'unhealthy',
    );
    if (unhealthyRequired.length === 0) {
      expect(body.ready).toBe(true);
    }
  });

  it('echoes a generated x-correlation-id header on every response', async () => {
    const response = await request(app.getHttpServer()).get('/health/live');
    expect(response.headers['x-correlation-id']).toBeTruthy();
  });
});
