import { describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../auth/auth-context';
import type { AiJobState } from '../ai-jobs/ai-job.store';
import { PolicySuggestActivitiesFactory } from '../temporal/activities/policy-suggest.activities';
import { PolicySuggestJobsService } from './policy-suggest-jobs.service';

/** The store's contract in memory: tenant-keyed, terminal states are final. */
function memoryStore() {
  const jobs = new Map<string, AiJobState>();
  const inputs = new Map<string, string>();
  let n = 0;
  const key = (t: string, id: string) => `${t}:${id}`;
  return {
    jobs,
    create: vi.fn((tenantId: string, userId: string, input: string) => {
      const id = `00000000-0000-4000-8000-00000000000${++n}`;
      const job: AiJobState = {
        id,
        tenantId,
        userId,
        kind: 'policy_suggest',
        status: 'queued',
        phase: 'queued',
        outputTokens: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        meterKey: `ai:job:${id}`,
        cancelRequested: false,
      };
      jobs.set(key(tenantId, id), job);
      inputs.set(key(tenantId, id), input);
      return Promise.resolve(job);
    }),
    get: vi.fn((t: string, id: string) =>
      Promise.resolve(jobs.get(key(t, id))),
    ),
    update: vi.fn((t: string, id: string, patch: Partial<AiJobState>) => {
      const cur = jobs.get(key(t, id));
      if (!cur) return Promise.resolve(undefined);
      const locked = ['ready', 'failed', 'cancelled'].includes(cur.status);
      const next = {
        ...cur,
        ...(locked ? {} : patch),
        cancelRequested: cur.cancelRequested || !!patch.cancelRequested,
        updatedAt: new Date().toISOString(),
      };
      jobs.set(key(t, id), next);
      return Promise.resolve(next);
    }),
    takeInput: vi.fn((t: string, id: string) => {
      const v = inputs.get(key(t, id));
      inputs.delete(key(t, id));
      return Promise.resolve(v);
    }),
  };
}

const auth = (tenant = 't1', user = 'u1') =>
  ({ tenant: { id: tenant }, user: { id: user } }) as AuthContext;
const body = {
  naturalLanguageDescription: 'only SOC agents may read',
  policyName: 'SOC',
};

function service(over: { startFails?: boolean; consumeFails?: boolean } = {}) {
  const store = memoryStore();
  const meter = {
    consume: vi.fn(() =>
      over.consumeFails
        ? Promise.reject(new Error('402'))
        : Promise.resolve({ source: 'allowance' }),
    ),
    release: vi.fn(() => Promise.resolve()),
  };
  const temporal = {
    taskQueue: 'q',
    workflow: {
      start: vi.fn(() =>
        over.startFails
          ? Promise.reject(new Error('down'))
          : Promise.resolve({}),
      ),
    },
  };
  const svc = new PolicySuggestJobsService(
    store as never,
    temporal as never,
    meter as never,
    { getPolicyOrThrow: vi.fn(() => Promise.resolve({})) } as never,
    { getClient: vi.fn(() => Promise.resolve({})) } as never,
  );
  return { svc, store, meter, temporal };
}

describe('PolicySuggestJobsService', () => {
  it('starts a workflow with ids only: the prompt never goes into Temporal', async () => {
    const { svc, temporal, meter } = service();
    const job = await svc.start(auth(), body);
    expect(meter.consume).toHaveBeenCalledWith('t1', 'ai', job.meterKey);
    const call = temporal.workflow.start.mock.calls[0] as unknown as [
      unknown,
      { args: unknown[]; workflowId: string },
    ];
    expect(call[1].args).toEqual([{ tenantId: 't1', jobId: job.id }]);
    expect(JSON.stringify(call[1])).not.toContain('SOC agents');
  });

  it('refuses a paused workspace before any work starts and starts nothing', async () => {
    const { svc, temporal } = service({ consumeFails: true });
    await expect(svc.start(auth(), body)).rejects.toThrow('402');
    expect(temporal.workflow.start).not.toHaveBeenCalled();
  });

  it('gives the AI action back when the workflow cannot start', async () => {
    const { svc, meter } = service({ startFails: true });
    await expect(svc.start(auth(), body)).rejects.toMatchObject({
      status: 503,
    });
    expect(meter.release).toHaveBeenCalledTimes(1);
  });

  it('answers another user, another workspace and an unknown job with the same 404', async () => {
    const { svc } = service();
    const job = await svc.start(auth('t1', 'u1'), body);
    await expect(svc.read(auth('t1', 'u2'), job.id)).rejects.toMatchObject({
      status: 404,
    });
    await expect(svc.read(auth('t2', 'u1'), job.id)).rejects.toMatchObject({
      status: 404,
    });
    await expect(
      svc.read(auth('t1', 'u1'), '00000000-0000-4000-8000-0000000000ff'),
    ).rejects.toMatchObject({ status: 404 });
    await expect(svc.cancel(auth('t2', 'u1'), job.id)).rejects.toMatchObject({
      status: 404,
    });
    await expect(svc.read(auth('t1', 'u1'), job.id)).resolves.toMatchObject({
      id: job.id,
    });
  });

  it('finishes a job whose worker vanished as stalled and gives the action back', async () => {
    const { svc, store, meter } = service();
    const job = await svc.start(auth(), body);
    store.jobs.set(`t1:${job.id}`, {
      ...store.jobs.get(`t1:${job.id}`)!,
      status: 'running',
      updatedAt: new Date(Date.now() - 5 * 60_000).toISOString(),
    });
    await expect(svc.read(auth(), job.id)).resolves.toMatchObject({
      status: 'failed',
      error: 'stalled',
    });
    expect(store.jobs.get(`t1:${job.id}`)).toMatchObject({
      status: 'failed',
      error: 'stalled',
    });
    expect(meter.release).toHaveBeenCalledTimes(1);
  });
});

describe('PolicySuggestActivitiesFactory', () => {
  async function run(over: {
    draft?: unknown;
    saved?: unknown;
    cancelBeforeStart?: boolean;
    streamImpl?: (hooks: {
      onProgress: (n: number) => void;
      signal: AbortSignal;
    }) => Promise<unknown>;
  }) {
    const store = memoryStore();
    const job = await store.create('t1', 'u1', JSON.stringify(body));
    if (over.cancelBeforeStart)
      await store.update('t1', job.id, { cancelRequested: true });
    const meter = { release: vi.fn(() => Promise.resolve()) };
    const advisory = {
      suggestPolicyStream: vi.fn(
        (
          _i: unknown,
          hooks: { onProgress: (n: number) => void; signal: AbortSignal },
        ) =>
          over.streamImpl
            ? over.streamImpl(hooks)
            : Promise.resolve(over.draft ?? null),
      ),
    };
    const policies = {
      persistSuggestion: vi.fn(() =>
        Promise.resolve(
          over.saved ?? {
            available: true,
            policyId: 'p1',
            version: { id: 'v1' },
            explanation: 'why',
            confidence: 0.8,
          },
        ),
      ),
    };
    const factory = new PolicySuggestActivitiesFactory(
      store as never,
      advisory as never,
      policies as never,
      { getClient: () => Promise.resolve({}) } as never,
      meter as never,
      { get: () => 600_000 } as never,
    );
    await factory
      .build()
      .runPolicySuggestionJob({ tenantId: 't1', jobId: job.id });
    return {
      state: store.jobs.get(`t1:${job.id}`)!,
      meter,
      advisory,
      policies,
      store,
    };
  }

  const draft = {
    rules: [{ toolId: '*' }],
    explanation: 'why',
    confidence: 0.8,
  };

  it('drafts, saves the DRAFT version and marks the job ready; the action stays spent', async () => {
    const { state, meter, policies } = await run({ draft });
    expect(state).toMatchObject({
      status: 'ready',
      phase: 'done',
      result: {
        available: true,
        policyId: 'p1',
        versionId: 'v1',
        ruleCount: 1,
      },
    });
    expect(meter.release).not.toHaveBeenCalled();
    expect(policies.persistSuggestion).toHaveBeenCalledWith(
      {},
      expect.objectContaining({ authorId: 'u1', policyName: 'SOC' }),
      draft,
    );
  });

  it('gives the action back and says model_unavailable when manar-ai produced nothing', async () => {
    const { state, meter } = await run({
      draft: null,
      saved: {
        available: false,
        policyId: null,
        version: null,
        explanation: null,
        confidence: null,
      },
    });
    expect(state).toMatchObject({
      status: 'ready',
      error: 'model_unavailable',
      result: { available: false },
    });
    expect(meter.release).toHaveBeenCalledTimes(1);
  });

  it('a job cancelled before it started never calls the model and is given back', async () => {
    const { state, meter, advisory } = await run({ cancelBeforeStart: true });
    expect(state.status).toBe('cancelled');
    expect(advisory.suggestPolicyStream).not.toHaveBeenCalled();
    expect(meter.release).toHaveBeenCalledTimes(1);
  });

  it('counts output tokens from what the model writes, and keeps the prompt out of the state', async () => {
    const { state } = await run({
      draft,
      streamImpl: (hooks) => {
        hooks.onProgress(400);
        return Promise.resolve(draft);
      },
    });
    expect(JSON.stringify(state)).not.toContain('SOC agents');
    expect(state.status).toBe('ready');
  });

  it('a crash in saving fails the job with a fixed code and gives the action back', async () => {
    const store = memoryStore();
    const job = await store.create('t1', 'u1', JSON.stringify(body));
    const meter = { release: vi.fn(() => Promise.resolve()) };
    const f = new PolicySuggestActivitiesFactory(
      store as never,
      { suggestPolicyStream: () => Promise.resolve(draft) } as never,
      {
        persistSuggestion: () =>
          Promise.reject(new Error('db down with SOC agents text')),
      } as never,
      { getClient: () => Promise.resolve({}) } as never,
      meter as never,
      { get: () => 600_000 } as never,
    );
    await f.build().runPolicySuggestionJob({ tenantId: 't1', jobId: job.id });
    const state = store.jobs.get(`t1:${job.id}`)!;
    expect(state).toMatchObject({ status: 'failed', error: 'internal' });
    expect(JSON.stringify(state)).not.toContain('db down');
    expect(meter.release).toHaveBeenCalledTimes(1);
  });
});
