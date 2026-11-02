import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import { status as grpcStatus } from '@grpc/grpc-js';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import { FakeAnalysisServiceServer } from '../../test/support/fake-analysis-service-server';
import {
  AI_ADVISORY_MAX_MESSAGE_BYTES,
  AiAdvisoryClient,
  dlpChunks,
} from './ai-advisory-client.service';

function fakeConfigService(
  overrides: Partial<AppConfig> = {},
): ConfigService<AppConfig, true> {
  const values: Partial<AppConfig> = {
    AI_ADVISORY_GRPC_TARGET: 'unset',
    AI_ADVISORY_TIMEOUT_MS: 300,
    AI_ADVISORY_DLP_TIMEOUT_MS: 300,
    AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 3,
    AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 200,
    AI_ADVISORY_LONGFORM_TIMEOUT_MS: 500,
    AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD: 3,
    AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS: 200,
    AI_ADVISORY_PROVIDER: 'ollama',
    ...overrides,
  };
  return {
    get: (key: keyof AppConfig) => values[key],
  } as unknown as ConfigService<AppConfig, true>;
}

/** A fake `ControlPrismaService` whose `tenant.findUnique` returns a fixed `allowExternalAi` value (or throws, for the fail-closed-on-error scenario) — never a real control DB connection. */
function fakeControlPrismaService(
  allowExternalAi: boolean | 'throw' = true,
  residency: 'UAE' | 'CUSTOM_REGION' | 'AIR_GAPPED' = 'UAE',
): ControlPrismaService {
  return {
    tenant: {
      findUnique: () => {
        if (allowExternalAi === 'throw') {
          throw new Error('control DB unreachable');
        }
        return Promise.resolve({ allowExternalAi, residency });
      },
    },
  } as unknown as ControlPrismaService;
}

const permissiveControl = fakeControlPrismaService(true);

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
      permissiveControl,
    );
    const result = await client.analyzeRisk({
      actionDescription: 'do a thing',
      context: '',
      tenantId: 'tenant-1',
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
      permissiveControl,
    );
    await expect(
      client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 'tenant-1',
      }),
    ).resolves.toBeNull();
    await expect(
      client.analyzePromptInjection({
        content: 'x',
        source: 'tool_output',
        tenantId: 'tenant-1',
      }),
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
      permissiveControl,
    );
    const result = await client.analyzeDlp({
      content: 'anything',
      tenantId: 'tenant-1',
    });
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
      permissiveControl,
    );
    const result = await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
    });
    expect(result).toBeNull();
  }, 10_000);

  it('an unreachable target returns null immediately, never throws', async () => {
    const client = new AiAdvisoryClient(
      fakeConfigService({
        AI_ADVISORY_GRPC_TARGET: '127.0.0.1:1', // nothing listens on port 1
        AI_ADVISORY_TIMEOUT_MS: 300,
      }),
      permissiveControl,
    );
    const result = await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
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
      permissiveControl,
    );

    // Two failures open the circuit.
    await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
    });
    await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
    });
    expect(fakeServer.callCounts.analyzeRisk).toBe(2);

    // Circuit now open -- further calls return null immediately without
    // ever reaching the server.
    const before = Date.now();
    const result = await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
    });
    const elapsedMs = Date.now() - before;
    expect(result).toBeNull();
    expect(fakeServer.callCounts.analyzeRisk).toBe(2); // unchanged -- circuit skipped the call
    expect(elapsedMs).toBeLessThan(50); // no timeout paid -- short-circuited immediately

    // After the cooldown elapses, the next call is let through as a trial.
    await new Promise((resolve) => setTimeout(resolve, 350));
    await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
    });
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
      permissiveControl,
    );

    await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
    }); // opens circuit
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
      tenantId: 'tenant-1',
    });
    expect(trialResult).not.toBeNull(); // half-open trial succeeded, circuit closed

    // A subsequent immediate failure should now take a fresh full failure
    // count to re-open the circuit (threshold is 1 here, so this alone
    // reopens it) -- confirms the breaker was actually reset, not just
    // coincidentally still "open but past cooldown".
    fakeServer.responseDelayMs = 500;
    const before = Date.now();
    await client.analyzeRisk({
      actionDescription: 'x',
      context: '',
      tenantId: 'tenant-1',
    });
    const elapsedMs = Date.now() - before;
    expect(elapsedMs).toBeGreaterThanOrEqual(50); // this call actually attempted the RPC (paid the timeout), proving the circuit was closed going in
  }, 10_000);

  /**
   * The headline regression this task exists to fix, plus the independence
   * the two lanes' timeouts/breakers must have from each other. Before this
   * task, every RPC (including the three long-form generation ones) shared
   * `AiAdvisoryClient`'s single `timeoutMs`/circuit-breaker state, so a
   * long-form call slower than the hot lane's ~2s budget always timed out,
   * and three such timeouts opened one shared breaker that also took
   * `analyzeRisk`/`analyzeDlp`/`analyzePromptInjection` dark for the
   * cooldown period.
   */
  describe('dlp lane and half-open trial (E-015, E-035)', () => {
    it("one tenant's failing DLP scans do not open the breaker for another tenant", async () => {
      fakeServer.responseDelayMs = 300;
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_DLP_TIMEOUT_MS: 50,
          AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 1,
          AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 10_000,
        }),
        permissiveControl,
      );
      await client.analyzeDlp({ content: 'x', tenantId: 'slow-tenant' }); // opens slow-tenant's breaker
      expect(fakeServer.callCounts.analyzeDlp).toBe(1);
      await client.analyzeDlp({ content: 'x', tenantId: 'slow-tenant' });
      expect(fakeServer.callCounts.analyzeDlp).toBe(1); // skipped: its breaker is open
      fakeServer.responseDelayMs = 0;
      const other = await client.analyzeDlp({
        content: 'x',
        tenantId: 'other',
      });
      expect(other).not.toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(2);
    }, 10_000);

    it('scans content over the gRPC cap whole, in chunks under it, and keeps the worst severity', async () => {
      const big = 'a'.repeat(5 * 1024 * 1024);
      const chunks = dlpChunks(big);
      expect(chunks.length).toBeGreaterThan(1);
      for (const c of chunks) {
        expect(Buffer.byteLength(c)).toBeLessThan(
          AI_ADVISORY_MAX_MESSAGE_BYTES,
        );
      }
      // every character is in some chunk
      expect(chunks.reduce((n, c) => n + c.length, 0)).toBeGreaterThanOrEqual(
        big.length,
      );
      fakeServer.dlpResult = { findings: [], overallSeverity: 4 };
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_DLP_TIMEOUT_MS: 5000,
        }),
        permissiveControl,
      );
      const result = await client.analyzeDlp({ content: big, tenantId: 't' });
      expect(fakeServer.callCounts.analyzeDlp).toBe(chunks.length);
      expect(result?.overallSeverity).toBe('SEVERITY_HIGH');
    }, 20_000);

    it('retries a transient UNAVAILABLE once inside the deadline', async () => {
      fakeServer.failNextWith = grpcStatus.UNAVAILABLE;
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_DLP_TIMEOUT_MS: 2000,
        }),
        permissiveControl,
      );
      const result = await client.analyzeDlp({ content: 'x', tenantId: 't' });
      expect(result).not.toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(2);
    });

    it('a secret straddling a chunk boundary is whole in one chunk', () => {
      const secret = 'S'.repeat(100);
      const size = 20_000;
      const content = 'x'.repeat(size - 50) + secret + 'y'.repeat(size);
      expect(dlpChunks(content, size).some((c) => c.includes(secret))).toBe(
        true,
      );
    });
    it('AnalyzeDlp gets its own deadline: an LLM-slow DLP answer past the hot budget still arrives', async () => {
      fakeServer.responseDelayMs = 400;
      fakeServer.dlpResult = { findings: [], overallSeverity: 1 };
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_TIMEOUT_MS: 100,
          AI_ADVISORY_DLP_TIMEOUT_MS: 2000,
        }),
        permissiveControl,
      );
      const dlp = await client.analyzeDlp({ content: 'x', tenantId: 't' });
      expect(dlp).not.toBeNull();
      expect(
        await client.analyzeRisk({
          actionDescription: 'x',
          context: '',
          tenantId: 't',
        }),
      ).toBeNull(); // the hot lane still times out at its own 100 ms
    }, 10_000);

    it('slow DLP calls open only the dlp breaker; risk keeps working', async () => {
      fakeServer.responseDelayMs = 300;
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_TIMEOUT_MS: 1000,
          AI_ADVISORY_DLP_TIMEOUT_MS: 50,
          AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 1,
          AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 10_000,
        }),
        permissiveControl,
      );
      await client.analyzeDlp({ content: 'x', tenantId: 't' }); // opens the dlp breaker
      fakeServer.riskResult = {
        score: 10,
        confidence: 0.5,
        signals: [],
        explanation: '',
        recommendedAction: 1,
      };
      const risk = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      expect(risk).not.toBeNull();
    }, 10_000);

    it('after the cooldown lets exactly one trial through, not every concurrent call', async () => {
      fakeServer.responseDelayMs = 300;
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_TIMEOUT_MS: 50,
          AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 1,
          AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 100,
        }),
        permissiveControl,
      );
      const risk = () =>
        client.analyzeRisk({
          actionDescription: 'x',
          context: '',
          tenantId: 't',
        });
      await risk(); // opens the breaker
      await new Promise((resolve) => setTimeout(resolve, 150));
      await Promise.all([risk(), risk(), risk(), risk()]);
      expect(fakeServer.callCounts.analyzeRisk).toBe(2); // the opener plus one trial
    }, 10_000);
  });

  describe('lane isolation (hot vs longform)', () => {
    it("1. a long-form RPC delayed past the hot lane's budget, but inside the long-form deadline, succeeds (today it fails without lanes)", async () => {
      fakeServer.responseDelayMs = 2500; // longer than the hot lane's timeout below, shorter than the long-form one
      fakeServer.incidentSummaryResult = {
        summary: 'A suspicious login pattern was observed.',
        keyEvents: ['login_failure', 'login_success'],
        probableRootCause: 'credential stuffing',
        recommendedNextSteps: ['rotate credentials'],
        confidence: 0.7,
        explanation: 'e',
      };
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_TIMEOUT_MS: 300, // hot lane -- would time out at this delay
          AI_ADVISORY_LONGFORM_TIMEOUT_MS: 5000, // long-form lane -- comfortably survives this delay
        }),
        permissiveControl,
      );
      const result = await client.summarizeIncident({
        description: 'x',
        relatedEvents: [],
        tenantId: 'tenant-1',
      });
      expect(result).not.toBeNull();
      expect(result?.summary).toBe('A suspicious login pattern was observed.');
    }, 10_000);

    it('2. tripping the long-form breaker leaves the hot lane fully functional -- after N long-form failures, analyzeRisk still returns a real score', async () => {
      fakeServer.responseDelayMs = 300; // exceeds the long-form timeout below on every call
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_TIMEOUT_MS: 2000,
          AI_ADVISORY_LONGFORM_TIMEOUT_MS: 100,
          AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD: 2,
          AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS: 10_000,
        }),
        permissiveControl,
      );

      // Trip the long-form breaker.
      await client.summarizeIncident({
        description: 'x',
        relatedEvents: [],
        tenantId: 't',
      });
      await client.summarizeIncident({
        description: 'x',
        relatedEvents: [],
        tenantId: 't',
      });
      // A third call would be skipped entirely if the long-form circuit is
      // now open -- confirms the trip actually happened, not just that two
      // calls failed.
      const skipped = await client.summarizeIncident({
        description: 'x',
        relatedEvents: [],
        tenantId: 't',
      });
      expect(skipped).toBeNull();
      expect(fakeServer.callCounts.summarizeIncident).toBe(2); // the third call never reached the server

      // The hot lane must be entirely unaffected -- a fast, successful
      // analyzeRisk call still goes through and returns a real score.
      fakeServer.responseDelayMs = 0;
      fakeServer.riskResult = {
        score: 55,
        confidence: 0.9,
        signals: ['s'],
        explanation: 'e',
        recommendedAction: 1,
      };
      const riskResult = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      expect(riskResult).not.toBeNull();
      expect(riskResult?.score).toBe(55);
      expect(fakeServer.callCounts.analyzeRisk).toBe(1); // reached the server -- the hot circuit was never open
    }, 10_000);

    it('3. tripping the hot breaker does not open the long-form breaker', async () => {
      fakeServer.responseDelayMs = 300; // exceeds the hot timeout below on every call
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_TIMEOUT_MS: 100,
          AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 2,
          AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 10_000,
          AI_ADVISORY_LONGFORM_TIMEOUT_MS: 5000,
        }),
        permissiveControl,
      );

      // Trip the hot breaker.
      await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      const skipped = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      expect(skipped).toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(2); // the third call never reached the server -- hot circuit open

      // The long-form lane must be entirely unaffected -- a fast,
      // successful summarizeIncident call still reaches the server.
      fakeServer.responseDelayMs = 0;
      fakeServer.incidentSummaryResult = {
        summary: 's',
        keyEvents: [],
        probableRootCause: '',
        recommendedNextSteps: [],
        confidence: 0.6,
        explanation: '',
      };
      const summaryResult = await client.summarizeIncident({
        description: 'x',
        relatedEvents: [],
        tenantId: 't',
      });
      expect(summaryResult).not.toBeNull();
      expect(fakeServer.callCounts.summarizeIncident).toBe(1); // reached the server -- the long-form circuit was never open
    }, 10_000);

    it('4. both lanes return null rather than throwing on a timeout', async () => {
      fakeServer.responseDelayMs = 5000;
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_TIMEOUT_MS: 100,
          AI_ADVISORY_LONGFORM_TIMEOUT_MS: 200,
        }),
        permissiveControl,
      );

      await expect(
        client.analyzeRisk({
          actionDescription: 'x',
          context: '',
          tenantId: 't',
        }),
      ).resolves.toBeNull();
      await expect(
        client.summarizeIncident({
          description: 'x',
          relatedEvents: [],
          tenantId: 't',
        }),
      ).resolves.toBeNull();
    }, 10_000);
  });

  /**
   * Phase 12a (Section 54, data residency enforcement). These assert at
   * the *network* level, not just "the function returned null" -- every
   * scenario checks `fakeServer.callCounts`, which only increments when
   * the fake gRPC server actually receives a real wire-protocol call, to
   * prove the RPC was never attempted at all when the residency gate
   * blocks it (the exact assertion the design spec's Testing section
   * requires).
   */
  describe('data residency enforcement (Section 54)', () => {
    const dlp = (client: AiAdvisoryClient) =>
      client.analyzeDlp({ content: 'x', tenantId: 't' });

    it('Azure OpenAI is external: a tenant with allowExternalAi=false never reaches it (E-016)', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'azure_openai',
        }),
        fakeControlPrismaService(false),
      );
      expect(await dlp(client)).toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(0);
    });

    it('an undeclared provider in production counts as external; in development it is the local default', async () => {
      const prod = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: undefined,
          NODE_ENV: 'production',
        }),
        fakeControlPrismaService(false),
      );
      expect(await dlp(prod)).toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(0);

      const dev = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: undefined,
          NODE_ENV: 'development',
        }),
        fakeControlPrismaService(false),
      );
      expect(await dlp(dev)).not.toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(1);
    });

    it('an air-gapped tenant never reaches an external provider, even with allowExternalAi=true', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'azure_openai',
        }),
        fakeControlPrismaService(true, 'AIR_GAPPED'),
      );
      expect(await dlp(client)).toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(0);
    });

    it('an external provider + a tenant with allowExternalAi=false never reaches the network', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(false),
      );
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 'tenant-no-external-ai',
      });
      expect(result).toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(0);
    });

    it('an external provider + a tenant with allowExternalAi=true DOES reach the network', async () => {
      fakeServer.riskResult = {
        score: 20,
        confidence: 0.5,
        signals: [],
        explanation: '',
        recommendedAction: 1,
      };
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(true),
      );
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 'tenant-allows-external-ai',
      });
      expect(result).not.toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(1);
    });

    it('a self-hosted provider (ollama) is never gated by allowExternalAi, even when false', async () => {
      fakeServer.riskResult = {
        score: 20,
        confidence: 0.5,
        signals: [],
        explanation: '',
        recommendedAction: 1,
      };
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'ollama',
        }),
        fakeControlPrismaService(false),
      );
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 'tenant-no-external-ai',
      });
      expect(result).not.toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(1);
    });

    it('applies identically to analyzeDlp and analyzePromptInjection -- no RPC attempted for either', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(false),
      );
      const dlpResult = await client.analyzeDlp({
        content: 'anything',
        tenantId: 'tenant-no-external-ai',
      });
      const injectionResult = await client.analyzePromptInjection({
        content: 'anything',
        source: 'tool_output',
        tenantId: 'tenant-no-external-ai',
      });
      expect(dlpResult).toBeNull();
      expect(injectionResult).toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(0);
      expect(fakeServer.callCounts.analyzePromptInjection).toBe(0);
    });

    it('fails CLOSED (treats as disallowed) when the tenant lookup itself errors, for an external provider', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService('throw'),
      );
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 'tenant-unknown',
      });
      expect(result).toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(0);
    });

    it('a residency block does not count toward the circuit breaker (a policy decision, not an outage)', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 1,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(false),
      );
      // Several residency-blocked calls in a row -- if these counted as
      // circuit-breaker failures, a threshold of 1 would open the circuit
      // after the first one, but that's an orthogonal mechanism this
      // policy check must never trip.
      await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      expect(fakeServer.callCounts.analyzeRisk).toBe(0);

      // Now switch this same tenant to allowed, and confirm the circuit is
      // still closed (a real call is actually attempted, not
      // short-circuited by an errantly-opened breaker).
      fakeServer.riskResult = {
        score: 15,
        confidence: 0.5,
        signals: [],
        explanation: '',
        recommendedAction: 1,
      };
      const allowedClient = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 1,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(true),
      );
      const result = await allowedClient.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      expect(result).not.toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(1);
    });
  });

  /**
   * Phase 15a (Section 53): a second, independent gate layered on top of
   * the `allowExternalAi` residency check above. Mirrors that suite's own
   * "assert at the network level, never just 'the function returned
   * null'" posture -- every scenario here checks
   * `fakeServer.callCounts`, which only increments on a real received
   * wire-protocol call.
   */
  describe('data classification enforcement (Section 53)', () => {
    it('a RESTRICTED classification blocks an external-provider call even when the tenant has allowExternalAi=true', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        // allowExternalAi=true -- the RESTRICTED gate must still block,
        // independent of this flag.
        fakeControlPrismaService(true),
      );
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 'tenant-allows-external-ai',
        classification: 'RESTRICTED',
      });
      expect(result).toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(0);
    });

    it('a RESTRICTED classification does not even consult the tenant\'s allowExternalAi flag (no control-DB lookup needed to decide "no")', async () => {
      let controlLookups = 0;
      const countingControl = {
        tenant: {
          findUnique: () => {
            controlLookups += 1;
            return Promise.resolve({ allowExternalAi: true });
          },
        },
      } as unknown as ControlPrismaService;
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        countingControl,
      );
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
        classification: 'RESTRICTED',
      });
      expect(result).toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(0);
      expect(controlLookups).toBe(0);
    });

    it('applies identically to analyzeDlp and analyzePromptInjection -- no RPC attempted for either when RESTRICTED', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(true),
      );
      const dlpResult = await client.analyzeDlp({
        content: 'anything',
        tenantId: 't',
        classification: 'RESTRICTED',
      });
      const injectionResult = await client.analyzePromptInjection({
        content: 'anything',
        source: 'tool_output',
        tenantId: 't',
        classification: 'RESTRICTED',
      });
      expect(dlpResult).toBeNull();
      expect(injectionResult).toBeNull();
      expect(fakeServer.callCounts.analyzeDlp).toBe(0);
      expect(fakeServer.callCounts.analyzePromptInjection).toBe(0);
    });

    it('a non-RESTRICTED classification (or none at all) is unaffected -- falls through to the ordinary allowExternalAi gate', async () => {
      fakeServer.riskResult = {
        score: 20,
        confidence: 0.5,
        signals: [],
        explanation: '',
        recommendedAction: 1,
      };
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(true),
      );
      const confidentialResult = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
        classification: 'CONFIDENTIAL',
      });
      const unclassifiedResult = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      expect(confidentialResult).not.toBeNull();
      expect(unclassifiedResult).not.toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(2);
    });

    it('a RESTRICTED classification does not count toward the circuit breaker (a policy decision, not an outage)', async () => {
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 1,
          AI_ADVISORY_PROVIDER: 'anthropic',
        }),
        fakeControlPrismaService(true),
      );
      await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
        classification: 'RESTRICTED',
      });
      await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
        classification: 'RESTRICTED',
      });
      expect(fakeServer.callCounts.analyzeRisk).toBe(0);

      fakeServer.riskResult = {
        score: 15,
        confidence: 0.5,
        signals: [],
        explanation: '',
        recommendedAction: 1,
      };
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
      });
      expect(result).not.toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(1);
    });

    it('a self-hosted provider (ollama) is never gated by classification, even RESTRICTED', async () => {
      fakeServer.riskResult = {
        score: 20,
        confidence: 0.5,
        signals: [],
        explanation: '',
        recommendedAction: 1,
      };
      const client = new AiAdvisoryClient(
        fakeConfigService({
          AI_ADVISORY_GRPC_TARGET: target,
          AI_ADVISORY_PROVIDER: 'ollama',
        }),
        fakeControlPrismaService(false),
      );
      const result = await client.analyzeRisk({
        actionDescription: 'x',
        context: '',
        tenantId: 't',
        classification: 'RESTRICTED',
      });
      expect(result).not.toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(1);
    });
  });
});
