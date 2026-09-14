import { describe, expect, it } from 'vitest';
import { evaluateReadiness, runProbe, summarizeReadiness } from './readiness';
import type { DependencyProbe, DependencyReport } from './readiness';

/**
 * The readiness engine's tests. These pin the three properties that decide
 * whether `/health/ready` protects the deployment or breaks it:
 *
 * 1. An **optional** dependency being down — specifically the AI advisory
 *    service — leaves this replica ready, flagged degraded. This is the
 *    invariant that keeps an AI outage from silently emptying the Service's
 *    endpoint list for an otherwise perfectly valid deterministic profile.
 * 2. A **required** dependency being down makes this replica unready.
 * 3. A probe that **hangs** is bounded by the timeout and reported `stale`,
 *    rather than hanging readiness itself until the kubelet gives up.
 *
 * Collaborators are plain in-memory fakes, no Nest DI container — the same
 * house style as `jwt-auth.guard.spec.ts` and `credential-broker.service.spec.ts`.
 */

/** A short-but-real budget so the timeout tests finish fast without fake timers. */
const TEST_TIMEOUT_MS = 25;

function probe(
  name: string,
  required: boolean,
  run: () => Promise<void | 'degraded'>,
): DependencyProbe {
  return { name, required, impact: `${name} impact`, run };
}

const healthy = (name: string, required: boolean): DependencyProbe =>
  probe(name, required, () => Promise.resolve(undefined));

const failing = (name: string, required: boolean): DependencyProbe =>
  probe(name, required, () =>
    Promise.reject(new Error(`${name} is unreachable`)),
  );

/** Never settles — models a dependency that accepts a connection and then goes silent. */
const hanging = (name: string, required: boolean): DependencyProbe =>
  probe(name, required, () => new Promise<void>(() => undefined));

describe('runProbe', () => {
  it('reports ok for a probe that resolves', async () => {
    const report = await runProbe(healthy('redis', false), TEST_TIMEOUT_MS);

    expect(report.status).toBe('ok');
    expect(report.required).toBe(false);
    expect(report.error).toBeUndefined();
  });

  it('reports degraded for a probe that resolves with "degraded"', async () => {
    const report = await runProbe(
      probe('openbao', false, () => Promise.resolve('degraded' as const)),
      TEST_TIMEOUT_MS,
    );

    expect(report.status).toBe('degraded');
  });

  it('reports unhealthy, with the failure message, for a probe that rejects', async () => {
    const report = await runProbe(failing('kafka', false), TEST_TIMEOUT_MS);

    expect(report.status).toBe('unhealthy');
    expect(report.error).toContain('kafka is unreachable');
  });

  it('bounds a hanging probe with a hard timeout and reports it as stale, not unhealthy', async () => {
    const startedAt = Date.now();
    const report = await runProbe(
      hanging('opensearch', false),
      TEST_TIMEOUT_MS,
    );
    const elapsed = Date.now() - startedAt;

    // The point of the test: this returned at all.
    expect(report.status).toBe('stale');
    expect(report.error).toContain(`${TEST_TIMEOUT_MS}ms budget`);
    // Generous upper bound — this asserts "bounded", not a precise latency.
    expect(elapsed).toBeLessThan(TEST_TIMEOUT_MS * 20);
  });

  it('does not let an abandoned probe’s late rejection escape as an unhandled rejection', async () => {
    let rejectLate: ((error: Error) => void) | undefined;
    const lateFailure = probe(
      'temporal',
      false,
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectLate = reject;
        }),
    );

    const report = await runProbe(lateFailure, TEST_TIMEOUT_MS);
    expect(report.status).toBe('stale');

    // Fire the rejection the engine already walked away from. If `runProbe`
    // had not attached its own catch, this would surface as an unhandled
    // rejection and, under Node's default policy, kill the process — turning
    // a slow dependency into the crash readiness exists to prevent.
    rejectLate?.(new Error('arrived after the deadline'));
    await new Promise((resolve) => setImmediate(resolve));
  });
});

describe('evaluateReadiness', () => {
  it('is ready and ok when every dependency is healthy', async () => {
    const report = await evaluateReadiness(
      [healthy('postgres-control', true), healthy('ai-advisory', false)],
      TEST_TIMEOUT_MS,
    );

    expect(report.ready).toBe(true);
    expect(report.status).toBe('ok');
    expect(report.dependencies['postgres-control']?.status).toBe('ok');
  });

  it('stays READY, reporting degraded, when the optional AI advisory service is down', async () => {
    const report = await evaluateReadiness(
      [
        healthy('postgres-control', true),
        healthy('openfga', true),
        failing('ai-advisory', false),
      ],
      TEST_TIMEOUT_MS,
    );

    // The release's hard requirement: an optional-AI outage must never
    // become a readiness failure for an otherwise valid deterministic
    // profile. The replica keeps serving; the outage is still reported.
    expect(report.ready).toBe(true);
    expect(report.status).toBe('degraded');
    expect(report.dependencies['ai-advisory']?.status).toBe('unhealthy');
    expect(report.dependencies['ai-advisory']?.required).toBe(false);
  });

  it('stays READY when the optional AI advisory probe hangs rather than fails', async () => {
    const report = await evaluateReadiness(
      [healthy('postgres-control', true), hanging('ai-advisory', false)],
      TEST_TIMEOUT_MS,
    );

    expect(report.ready).toBe(true);
    expect(report.status).toBe('degraded');
    expect(report.dependencies['ai-advisory']?.status).toBe('stale');
  });

  it('is NOT ready when a required dependency is unhealthy', async () => {
    const report = await evaluateReadiness(
      [failing('postgres-control', true), healthy('ai-advisory', false)],
      TEST_TIMEOUT_MS,
    );

    expect(report.ready).toBe(false);
    expect(report.status).toBe('unhealthy');
    expect(report.dependencies['postgres-control']?.status).toBe('unhealthy');
  });

  it('is NOT ready when a required dependency’s probe times out', async () => {
    const report = await evaluateReadiness(
      [hanging('openfga', true), healthy('postgres-control', true)],
      TEST_TIMEOUT_MS,
    );

    // A required dependency we cannot reach a verdict on is not a reason to
    // keep taking traffic — "stale" is honest about *why*, not a pass.
    expect(report.ready).toBe(false);
    expect(report.status).toBe('unhealthy');
    expect(report.dependencies['openfga']?.status).toBe('stale');
  });

  it('runs probes concurrently, so total time tracks the slowest probe rather than their sum', async () => {
    const startedAt = Date.now();
    await evaluateReadiness(
      [
        hanging('a', false),
        hanging('b', false),
        hanging('c', false),
        hanging('d', false),
      ],
      TEST_TIMEOUT_MS,
    );
    const elapsed = Date.now() - startedAt;

    // Sequential execution would take at least 4x the budget; this asserts
    // it stayed well under that. Nine dependencies at a 2s budget each is
    // 18s sequentially — far past any sane kubelet timeoutSeconds.
    expect(elapsed).toBeLessThan(TEST_TIMEOUT_MS * 3);
  });

  it('reports every dependency in the body even when one of them fails readiness', async () => {
    const report = await evaluateReadiness(
      [
        failing('postgres-control', true),
        failing('kafka', false),
        healthy('redis', false),
      ],
      TEST_TIMEOUT_MS,
    );

    expect(Object.keys(report.dependencies).sort()).toEqual([
      'kafka',
      'postgres-control',
      'redis',
    ]);
    expect(report.dependencies['kafka']?.impact).toBe('kafka impact');
  });
});

describe('summarizeReadiness', () => {
  const report = (
    status: DependencyReport['status'],
    required: boolean,
  ): DependencyReport => ({
    status,
    required,
    impact: 'test',
    durationMs: 1,
  });

  it('treats every non-ok status on an OPTIONAL dependency as degraded-but-ready', () => {
    for (const status of ['degraded', 'stale', 'unhealthy'] as const) {
      expect(summarizeReadiness({ optional: report(status, false) })).toEqual({
        status: 'degraded',
        ready: true,
      });
    }
  });

  it('treats every non-ok status on a REQUIRED dependency as unready', () => {
    for (const status of ['degraded', 'stale', 'unhealthy'] as const) {
      expect(summarizeReadiness({ required: report(status, true) })).toEqual({
        status: 'unhealthy',
        ready: false,
      });
    }
  });

  it('is ok and ready when there is nothing to report', () => {
    expect(summarizeReadiness({})).toEqual({ status: 'ok', ready: true });
  });
});
