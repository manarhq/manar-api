import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { FakeAnalysisServiceServer } from '../../test/support/fake-analysis-service-server';
import { AiAdvisoryClient } from './ai-advisory-client.service';

function fakeConfigService(
  overrides: Partial<AppConfig> = {},
): ConfigService<AppConfig, true> {
  const values: Partial<AppConfig> = {
    AI_ADVISORY_GRPC_TARGET: 'unset',
    AI_ADVISORY_TIMEOUT_MS: 300,
    AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 3,
    AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 200,
    ...overrides,
  };
  return {
    get: (key: keyof AppConfig) => values[key],
  } as unknown as ConfigService<AppConfig, true>;
}

/**
 * Unit-level coverage of `AiAdvisoryClient`'s own resilience mechanisms
 * (timeout, circuit breaker, the confidence==0 fail-secure-marker
 * convention) against a real gRPC server implementing the identical
 * `AnalysisService` contract (`FakeAnalysisServiceServer` — see that
 * class's doc comment for why this is a real wire-protocol round trip, not
 * a mock). `test/ai-advisory.e2e-spec.ts` covers the mandatory end-to-end
 * pipeline scenarios (against the real `manar-ai` container and this same
 * fake server, as appropriate); this spec is scoped to `AiAdvisoryClient`
 * in isolation.
 */
describe('AiAdvisoryClient', () => {
  let fakeServer: FakeAnalysisServiceServer;
  let target: string;

  beforeEach(async () => {
    fakeServer = new FakeAnalysisServiceServer();
    target = await fakeServer.start();
  });

  afterEach(async () => {
    await fakeServer.stop();
  });

  it('returns a real advisory on a normal, fast, high-confidence response', async () => {
    fakeServer.riskResult = {
      score: 42,
      confidence: 0.8,
      signals: ['s1'],
      explanation: 'e',
      recommendedAction: 2, // RECOMMENDED_ACTION_REVIEW
    };
    const client = new AiAdvisoryClient(
      fakeConfigService({ AI_ADVISORY_GRPC_TARGET: target }),
    );
    const result = await client.analyzeRisk({
      actionDescription: 'do a thing',
      context: '',
    });
    expect(result).toEqual({
      score: 42,
      confidence: 0.8,
      signals: ['s1'],
      explanation: 'e',
      recommendedAction: 'RECOMMENDED_ACTION_REVIEW',
    });
  });

  it('treats confidence==0 on AnalyzeRisk/AnalyzePromptInjection as "no advisory" (manar-ai\'s own fail-secure marker convention)', async () => {
    fakeServer.riskResult = {
      score: 75,
      confidence: 0,
      signals: ['analysis_unavailable:connection'],
      explanation: 'failure marker',
      recommendedAction: 2,
    };
    fakeServer.promptInjectionResult = {
      detected: true,
      confidence: 0,
      indicators: ['analysis_unavailable:connection'],
      explanation: 'failure marker',
    };
    const client = new AiAdvisoryClient(
      fakeConfigService({ AI_ADVISORY_GRPC_TARGET: target }),
    );
    await expect(
      client.analyzeRisk({ actionDescription: 'x', context: '' }),
    ).resolves.toBeNull();
    await expect(
      client.analyzePromptInjection({ content: 'x', source: 'tool_output' }),
    ).resolves.toBeNull();
  });

  it('analyzeDlp returns the result as-is even when it carries only a zero-confidence system marker finding (deterministic findings must always flow through)', async () => {
    fakeServer.dlpResult = {
      findings: [
        {
          type: 7, // TYPE_OTHER
          confidence: 0,
          redactedPreview: 'analysis_unavailable:connection',
          source: 'system',
        },
      ],
      overallSeverity: 3, // SEVERITY_MEDIUM
    };
    const client = new AiAdvisoryClient(
      fakeConfigService({ AI_ADVISORY_GRPC_TARGET: target }),
    );
    const result = await client.analyzeDlp({ content: 'anything' });
    expect(result).not.toBeNull();
    expect(result?.overallSeverity).toBe('SEVERITY_MEDIUM');
    expect(result?.findings).toHaveLength(1);
  });

  it('a slow response beyond the configured timeout returns null, never throws', async () => {
    fakeServer.responseDelayMs = 1000;
    const client = new AiAdvisoryClient(
      fakeConfigService({
        AI_ADVISORY_GRPC_TARGET: target,
        AI_ADVISORY_TIMEOUT_MS: 100,
      }),
    );
    const result = await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
    });
    expect(result).toBeNull();
  }, 10_000);

  it('an unreachable target returns null immediately, never throws', async () => {
    const client = new AiAdvisoryClient(
      fakeConfigService({
        AI_ADVISORY_GRPC_TARGET: '127.0.0.1:1', // nothing listens on port 1
        AI_ADVISORY_TIMEOUT_MS: 300,
      }),
    );
    const result = await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
    });
    expect(result).toBeNull();
  });

  it('circuit breaker opens after the configured consecutive-failure threshold, then skips calls entirely (no RPC attempted) until the cooldown elapses', async () => {
    fakeServer.responseDelayMs = 500; // guarantees a timeout every call
    const client = new AiAdvisoryClient(
      fakeConfigService({
        AI_ADVISORY_GRPC_TARGET: target,
        AI_ADVISORY_TIMEOUT_MS: 50,
        AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 2,
        AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 300,
      }),
    );

    // Two failures open the circuit.
    await client.analyzeRisk({ actionDescription: 'x', context: '' });
    await client.analyzeRisk({ actionDescription: 'x', context: '' });
    expect(fakeServer.callCounts.analyzeRisk).toBe(2);

    // Circuit now open -- further calls return null immediately without
    // ever reaching the server.
    const before = Date.now();
    const result = await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
    });
    const elapsedMs = Date.now() - before;
    expect(result).toBeNull();
    expect(fakeServer.callCounts.analyzeRisk).toBe(2); // unchanged -- circuit skipped the call
    expect(elapsedMs).toBeLessThan(50); // no timeout paid -- short-circuited immediately

    // After the cooldown elapses, the next call is let through as a trial.
    await new Promise((resolve) => setTimeout(resolve, 350));
    await client.analyzeRisk({ actionDescription: 'x', context: '' });
    expect(fakeServer.callCounts.analyzeRisk).toBe(3); // the trial call did reach the server
  }, 10_000);

  it('a success after the circuit opens (half-open trial) closes the circuit again', async () => {
    fakeServer.responseDelayMs = 500;
    const client = new AiAdvisoryClient(
      fakeConfigService({
        AI_ADVISORY_GRPC_TARGET: target,
        AI_ADVISORY_TIMEOUT_MS: 50,
        AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 1,
        AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 200,
      }),
    );

    await client.analyzeRisk({ actionDescription: 'x', context: '' }); // opens circuit
    await new Promise((resolve) => setTimeout(resolve, 250)); // cooldown elapses
    fakeServer.responseDelayMs = 0; // server recovers
    fakeServer.riskResult = {
      score: 10,
      confidence: 0.5,
      signals: [],
      explanation: '',
      recommendedAction: 1,
    };
    const trialResult = await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
    });
    expect(trialResult).not.toBeNull(); // half-open trial succeeded, circuit closed

    // A subsequent immediate failure should now take a fresh full failure
    // count to re-open the circuit (threshold is 1 here, so this alone
    // reopens it) -- confirms the breaker was actually reset, not just
    // coincidentally still "open but past cooldown".
    fakeServer.responseDelayMs = 500;
    const before = Date.now();
    await client.analyzeRisk({ actionDescription: 'x', context: '' });
    const elapsedMs = Date.now() - before;
    expect(elapsedMs).toBeGreaterThanOrEqual(50); // this call actually attempted the RPC (paid the timeout), proving the circuit was closed going in
  }, 10_000);
});
