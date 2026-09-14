import { ServiceUnavailableException } from '@nestjs/common';
import { describe, it, expect } from 'vitest';
import { HealthController } from './health.controller';
import type { ReadinessReport } from './readiness';
import type { ReadinessService } from './readiness.service';

/**
 * The controller's own contract: which status code each verdict produces,
 * and that the per-dependency detail survives into the body either way.
 * `readiness.spec.ts` and `readiness.service.spec.ts` cover how the verdict
 * is reached.
 */

function report(overrides: Partial<ReadinessReport> = {}): ReadinessReport {
  return {
    status: 'ok',
    ready: true,
    checkedAt: '2026-11-11T00:00:00.000Z',
    dependencies: {
      'postgres-control': {
        status: 'ok',
        required: true,
        impact: 'control plane',
        durationMs: 1,
      },
    },
    ...overrides,
  };
}

function makeController(result: ReadinessReport): HealthController {
  const readinessService = {
    check: () => Promise.resolve(result),
  } as unknown as ReadinessService;

  return new HealthController(readinessService);
}

describe('HealthController', () => {
  it('GET /health/live reports ok without consulting any dependency', () => {
    // Constructed with a readiness service that would throw if touched:
    // liveness must depend on nothing but this process, because its failure
    // mode is "restart every replica".
    const readinessService = {
      check: () => {
        throw new Error('liveness must not probe dependencies');
      },
    } as unknown as ReadinessService;

    expect(new HealthController(readinessService).live()).toEqual({
      status: 'ok',
    });
  });

  it('GET /health/ready returns the full report when ready', async () => {
    const expected = report();
    await expect(makeController(expected).ready()).resolves.toEqual(expected);
  });

  it('GET /health/ready returns 200 with the report when merely degraded', async () => {
    const degraded = report({
      status: 'degraded',
      dependencies: {
        'ai-advisory': {
          status: 'unhealthy',
          required: false,
          impact: 'optional AI advice only',
          durationMs: 2,
        },
      },
    });

    // Degraded is still ready — the replica keeps taking traffic.
    await expect(makeController(degraded).ready()).resolves.toEqual(degraded);
  });

  it('GET /health/ready raises a 503 carrying the same report when not ready', async () => {
    const unready = report({ status: 'unhealthy', ready: false });

    await expect(makeController(unready).ready()).rejects.toThrow(
      ServiceUnavailableException,
    );

    // The 503's body is the report, not a bare error — an operator looking
    // at a failing pod gets the same per-dependency detail a 200 gives.
    const error = await makeController(unready)
      .ready()
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expect((error as ServiceUnavailableException).getResponse()).toEqual(
      unready,
    );
  });
});
