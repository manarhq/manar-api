import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import { HttpException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { AgentContext } from '../agent-mtls/agent-context';
import type {
  AiAdvisoryClient,
  DlpAdvisory,
} from '../ai-advisory/ai-advisory-client.service';
import type { AuditService } from '../audit/audit.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { KillSwitchService } from '../kill-switches/kill-switch.service';
import { TasksService } from '../tasks/tasks.service';
import { allowAllCatalog } from '../platform/catalog.fakes';
import type { CatalogService } from '../platform/catalog.service';
import { AgentTaskAccessService } from './agent-task-access.service';
import {
  AnthropicStreamGuard,
  anthropicError,
  parseSse,
  type SseEvent,
} from './llm-anthropic';
import {
  LlmAnthropicService,
  replyStream,
  type AnthropicReply,
} from './llm-anthropic.service';
import type { LlmBudgetStore } from './llm-budget.store';
import { LlmProxyService } from './llm-proxy.service';
import { LlmUpstreamClient } from './llm-upstream.client';

type Json = Record<string, unknown>;

const AGENT: AgentContext = {
  tenant: { id: 'tenant-1', slug: 't' },
  agent: { id: 'agent-1', slug: 'a', identifier: 'agent://t/a' },
  certificate: { serialNumber: 'AB' },
};
const SERVER_KEY = 'server-side-test-key';
const CLEAN: DlpAdvisory = { findings: [], overallSeverity: 'SEVERITY_NONE' };
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl';

/** A local stand-in for both upstreams: Anthropic `/v1/messages` and OpenAI `/v1/chat/completions`. */
class FakeUpstream {
  calls: { path: string; headers: IncomingHttpHeaders; body: Json }[] = [];
  handler: (body: Json, res: ServerResponse) => void | Promise<void> = (
    _b,
    res,
  ) => json(res, 200, message());
  url = '';
  private server: Server | undefined;

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      let raw = '';
      req.on('data', (c: Buffer) => (raw += c.toString('utf8')));
      req.on('end', () => {
        const body = JSON.parse(raw || '{}') as Json;
        this.calls.push({ path: req.url ?? '', headers: req.headers, body });
        void this.handler(body, res);
      });
    });
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  stop(): Promise<void> {
    return new Promise((r) => this.server!.close(() => r()));
  }
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

const sseText = (type: string, data: Json) =>
  `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;

function message(
  content: Json[] = [{ type: 'text', text: 'Done.' }],
  usage?: Json,
): Json {
  return {
    id: 'msg_1',
    type: 'message',
    role: 'assistant',
    model: 'claude-test',
    content,
    stop_reason: 'end_turn',
    stop_sequence: null,
    usage: usage ?? {
      input_tokens: 30,
      output_tokens: 10,
      cache_creation_input_tokens: 5,
      cache_read_input_tokens: 100,
    },
  };
}

/** The upstream stream for `deltas`: start, one text block, then the final usage and stop. */
function streamEvents(deltas: string[]): string[] {
  return [
    sseText('message_start', {
      message: {
        ...message([]),
        usage: {
          input_tokens: 30,
          output_tokens: 1,
          cache_read_input_tokens: 100,
        },
      },
    }),
    sseText('content_block_start', {
      index: 0,
      content_block: { type: 'text', text: '' },
    }),
    sseText('ping', {}),
    ...deltas.map((text) =>
      sseText('content_block_delta', {
        index: 0,
        delta: { type: 'text_delta', text },
      }),
    ),
    sseText('content_block_stop', { index: 0 }),
    sseText('message_delta', {
      delta: { stop_reason: 'end_turn', stop_sequence: null },
      usage: { output_tokens: 7 },
    }),
    sseText('message_stop', {}),
  ];
}

function streamFrom(chunks: string[], hold?: Promise<void>) {
  return async (_b: Json, res: ServerResponse) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(chunks[0]);
    await hold;
    for (const c of chunks.slice(1)) res.write(c);
    res.end();
  };
}

async function collect(reply: AnthropicReply, onEvent?: (e: SseEvent) => void) {
  if (!('stream' in reply)) throw new Error('expected a stream');
  let text = '';
  for await (const chunk of reply.stream) {
    text += chunk;
    for (const raw of chunk.split('\n\n').filter(Boolean))
      onEvent?.(parseSse(raw)!);
  }
  return text
    .split('\n\n')
    .filter(Boolean)
    .map((raw) => parseSse(raw)!);
}

const upstream = new FakeUpstream();
beforeAll(() => upstream.start());
afterAll(() => upstream.stop());
beforeEach(() => {
  upstream.calls = [];
  upstream.handler = (_b, res) => json(res, 200, message());
});

function setup(
  opts: {
    env?: Json;
    killed?: string;
    used?: number;
    advisory?: DlpAdvisory | null;
  } = {},
) {
  const task = {
    id: 'task-1',
    name: 'n',
    description: null,
    parentTaskId: null,
    requesterId: 'u',
    assignedAgentId: 'agent-1',
    status: 'ACTIVE',
    startsAt: new Date(Date.now() - 60_000),
    expiresAt: new Date(Date.now() + 3_600_000),
    maxExecutions: null,
    executionCount: 0,
    allowedToolActions: [],
    allowedResourceSelectors: [],
    forbiddenActions: [],
    riskCeiling: 20,
    createdAt: new Date(),
  };
  const tenantClient = {
    task: { findUnique: vi.fn().mockResolvedValue(task) },
  };
  const tenantDatabaseManager = {
    getClient: vi.fn().mockResolvedValue(tenantClient),
  } as unknown as TenantDatabaseManager;
  const killSwitchService = {
    checkAll: vi
      .fn()
      .mockResolvedValue(
        opts.killed
          ? { killed: true, scope: 'AGENT', reason: opts.killed }
          : { killed: false },
      ),
  } as unknown as KillSwitchService;
  const llmGate = vi.fn().mockResolvedValue({ route: null, quota: null });
  const catalog = {
    ...allowAllCatalog(),
    llmGate,
    state: vi.fn().mockResolvedValue({ model: null }),
  } as unknown as CatalogService;
  const access = new AgentTaskAccessService(
    tenantDatabaseManager,
    killSwitchService,
    new TasksService(null as never, null as never, killSwitchService),
    catalog,
  );
  const thinking = new Set<string>();
  const budget = {
    rememberThinking: vi.fn((_t: string, task: string, hmacs: string[]) => {
      hmacs.forEach((h) => thinking.add(`${task}:${h}`));
      return Promise.resolve();
    }),
    knowsThinking: vi.fn((_t: string, task: string, hmacs: string[]) =>
      Promise.resolve(hmacs.every((h) => thinking.has(`${task}:${h}`))),
    ),
    used: vi.fn().mockResolvedValue(opts.used ?? 0),
    add: vi
      .fn()
      .mockImplementation((_t, _k, n: number) => (opts.used ?? 0) + n),
  };
  const aiAdvisory = {
    analyzeDlp: vi
      .fn()
      .mockResolvedValue(opts.advisory === undefined ? CLEAN : opts.advisory),
  };
  const audit = {
    record: vi.fn().mockResolvedValue({}),
    recordSafely: vi.fn().mockResolvedValue({}),
  };
  const values: Json = {
    LLM_TASK_TOKEN_BUDGET: 200_000,
    LLM_UPSTREAM_TIMEOUT_MS: 5_000,
    APPROVAL_GRANT_SIGNING_SECRET: 'unit-test-only-signing-secret',
    LLM_PROVIDER: 'ollama',
    LLM_MODEL: 'fixture-model',
    LLM_OLLAMA_BASE_URL: `${upstream.url}/v1`,
    LLM_ANTHROPIC_PROVIDER: 'anthropic',
    LLM_ANTHROPIC_BASE_URL: upstream.url,
    ANTHROPIC_API_KEY: SERVER_KEY,
    LLM_ANTHROPIC_MODELS: 'claude-test,claude-small',
    LLM_ANTHROPIC_UAE_RESIDENT: 'false',
    LLM_ANTHROPIC_BETAS:
      'interleaved-thinking-2025-05-14,context-management-2025-06-27',
    LLM_STREAM_MAX_MS: 900_000,
    LLM_ANTHROPIC_STREAM_DLP: 'buffer',
    ...opts.env,
  };
  const config = {
    get: (k: string) => values[k],
  } as unknown as ConfigService<AppConfig, true>;
  const client = new LlmUpstreamClient(config);
  const proxy = new LlmProxyService(
    access,
    budget as unknown as LlmBudgetStore,
    client,
    aiAdvisory as unknown as AiAdvisoryClient,
    audit as unknown as AuditService,
    tenantDatabaseManager,
    config,
    catalog,
  );
  const service = new LlmAnthropicService(
    proxy,
    client,
    config,
    catalog,
    budget as unknown as LlmBudgetStore,
  );
  const send = (
    body: Json,
    client = {},
    signal = new AbortController().signal,
  ) => service.messages(AGENT, 'task-1', body, client, signal);
  const audited = () =>
    [...audit.record.mock.calls, ...audit.recordSafely.mock.calls].map(
      (c) => (c[2] as { data: Json }).data,
    );
  return { service, send, budget, audit, audited, llmGate, aiAdvisory };
}

const request = (extra: Json = {}): Json => ({
  model: 'claude-test',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'List the files.' }],
  ...extra,
});

async function refused(
  promise: Promise<unknown>,
  status: number,
  reason: string,
) {
  await expect(promise).rejects.toMatchObject({
    status,
    response: expect.objectContaining({ reason }) as unknown,
  });
}

/** A signature as the upstream issues it: canonical base64. */
const sig = (seed: number) =>
  Buffer.from(
    Array.from({ length: 96 }, (_, i) => (i * 31 + seed) % 256),
  ).toString('base64');

describe('LlmAnthropicService: providers and request policy', () => {
  it('is 404 anthropic_disabled for provider none, without a key, and without a model list', async () => {
    for (const env of [
      { LLM_ANTHROPIC_PROVIDER: 'none' },
      { ANTHROPIC_API_KEY: undefined },
      { LLM_ANTHROPIC_MODELS: '' },
    ]) {
      await refused(setup({ env }).send(request()), 404, 'anthropic_disabled');
    }
    expect(upstream.calls).toHaveLength(0);
  });

  it('runs the task check before everything: disabled endpoint, bad body and shape refusals all yield to it', async () => {
    for (const [env, body] of [
      [
        {},
        request({
          tools: [{ type: 'web_search_20250305', name: 'w' }],
          foo: 1,
        }),
      ],
      [{ LLM_ANTHROPIC_PROVIDER: 'none' }, request()],
      [{}, { model: 'claude-test' }],
    ] as [Json, Json][]) {
      const { send, audited } = setup({ env, killed: 'agent_killed' });
      await refused(send(body), 403, 'agent_killed');
      const row = audited()[0]!;
      expect(row).toMatchObject({
        outcome: 'DENIED',
        reason: 'agent_killed',
        claimedTaskIdSha256: expect.stringMatching(/^[0-9a-f]{64}$/) as unknown,
      });
      expect(row.taskId).toBeUndefined();
      expect(JSON.stringify(row)).not.toContain('task-1');
    }
    expect(upstream.calls).toHaveLength(0);
  });

  it('records a bad body and a disabled endpoint against the verified task', async () => {
    const bad = setup();
    await expect(bad.send({ model: 'claude-test' })).rejects.toMatchObject({
      status: 400,
    });
    expect(bad.audited()[0]).toMatchObject({
      taskId: 'task-1',
      outcome: 'DENIED',
    });
    const off = setup({ env: { LLM_ANTHROPIC_PROVIDER: 'none' } });
    await refused(off.send(request()), 404, 'anthropic_disabled');
    expect(off.audited()[0]).toMatchObject({
      taskId: 'task-1',
      reason: 'anthropic_disabled',
    });
  });

  it('stops with 429 llm_budget_exhausted once the task budget is used', async () => {
    await refused(
      setup({ used: 200_000 }).send(request()),
      429,
      'llm_budget_exhausted',
    );
    expect(upstream.calls).toHaveLength(0);
  });

  it('refuses a model the install does not serve (no substitution)', async () => {
    await refused(
      setup().send(request({ model: 'claude-other' })),
      400,
      'llm_model_not_served',
    );
    expect(upstream.calls).toHaveLength(0);
  });

  it('refuses unknown top-level fields, provider-side connectors and server tools in Anthropic wording', async () => {
    const { send } = setup();
    for (const extra of [
      { foo: 'x' },
      { mcp_servers: [] },
      { container: 'c' },
    ]) {
      const r = send(request(extra));
      await refused(r, 400, 'llm_request_field_not_allowed');
      await expect(r).rejects.toMatchObject({
        response: {
          error: {
            message: expect.stringContaining(
              'Extra inputs are not permitted',
            ) as unknown,
          },
        },
      });
    }
    const tool = send(
      request({ tools: [{ type: 'web_search_20250305', name: 'web_search' }] }),
    );
    await refused(tool, 400, 'llm_server_tool_not_allowed');
    await expect(tool).rejects.toMatchObject({
      response: {
        error: {
          message: expect.stringContaining(
            "Input tag 'web_search_20250305'",
          ) as unknown,
        },
      },
    });
    expect(upstream.calls).toHaveLength(0);
  });

  it('refuses content DLP cannot read', async () => {
    const image = {
      type: 'image',
      source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0KGgo=' },
    };
    await refused(
      setup().send(
        request({
          messages: [
            {
              role: 'user',
              content: [
                { type: 'tool_result', tool_use_id: 't1', content: [image] },
              ],
            },
          ],
        }),
      ),
      403,
      'dlp_unscannable_content',
    );
    expect(upstream.calls).toHaveLength(0);
  });

  it('forwards only allow-listed anthropic-beta values and refuses a malformed anthropic-version', async () => {
    const { send } = setup();
    await send(request(), {
      version: '2023-06-01',
      beta: 'interleaved-thinking-2025-05-14, oauth-2025-04-20,context-management-2025-06-27',
    });
    expect(upstream.calls[0]!.headers['anthropic-beta']).toBe(
      'interleaved-thinking-2025-05-14,context-management-2025-06-27',
    );
    await send(request(), { beta: 'oauth-2025-04-20' });
    expect(upstream.calls[1]!.headers['anthropic-beta']).toBeUndefined();
    expect(upstream.calls[1]!.headers['anthropic-version']).toBe('2023-06-01');
    await refused(
      send(request(), { version: '2023-06-01\r\nx-api-key: stolen' }),
      400,
      'invalid_anthropic_version',
    );
    expect(upstream.calls).toHaveLength(2);
  });
});

describe('LlmAnthropicService: thinking signatures', () => {
  const history = (signature: string, extra: Json = {}) =>
    request({
      messages: [
        { role: 'user', content: 'Hi' },
        {
          role: 'assistant',
          content: [
            { type: 'thinking', thinking: 'Plan.', signature, ...extra },
            { type: 'text', text: 'Hello' },
          ],
        },
        { role: 'user', content: 'Go on' },
      ],
    });

  it('passes a signature this proxy returned for the task unchanged, and refuses one it did not', async () => {
    const { send } = setup();
    const issued = sig(1);
    upstream.handler = (_b, res) =>
      json(
        res,
        200,
        message([
          { type: 'thinking', thinking: 'Plan.', signature: issued },
          { type: 'text', text: 'Hello' },
        ]),
      );
    await send(request());
    upstream.handler = (_b, res) => json(res, 200, message());
    await send(history(issued));
    expect(
      ((upstream.calls[1]!.body.messages as Json[])[1]!.content as Json[])[0],
    ).toEqual({ type: 'thinking', thinking: 'Plan.', signature: issued });

    const forged = send(history(sig(2)));
    await refused(forged, 400, 'unknown_thinking_signature');
    await expect(forged).rejects.toMatchObject({
      response: {
        error: {
          message: expect.stringContaining(
            'Invalid `signature` in `thinking` block',
          ) as unknown,
        },
      },
    });
    // A secret in the base64 alphabet (an AWS-style key) is not a signature this proxy issued.
    await refused(
      send(history('AKIAIOSFODNN7EXAMPLE')),
      400,
      'unknown_thinking_signature',
    );
    expect(upstream.calls).toHaveLength(2);
  });

  it('remembers signatures from a streamed answer too (both stream modes)', async () => {
    for (const mode of ['buffer', 'incremental']) {
      upstream.calls = [];
      const { send } = setup({ env: { LLM_ANTHROPIC_STREAM_DLP: mode } });
      const issued = sig(mode.length);
      upstream.handler = streamFrom([
        sseText('message_start', { message: message([]) }),
        sseText('content_block_start', {
          index: 0,
          content_block: { type: 'thinking', thinking: '', signature: '' },
        }),
        sseText('content_block_delta', {
          index: 0,
          delta: { type: 'thinking_delta', thinking: 'Plan.' },
        }),
        sseText('content_block_delta', {
          index: 0,
          delta: { type: 'signature_delta', signature: issued },
        }),
        sseText('content_block_stop', { index: 0 }),
        sseText('message_delta', {
          delta: { stop_reason: 'end_turn' },
          usage: { output_tokens: 3 },
        }),
        sseText('message_stop', {}),
      ]);
      const events = await collect(await send(request({ stream: true })));
      expect(
        events.some(
          (e) => (e.data.delta as Json | undefined)?.signature === issued,
        ),
      ).toBe(true);
      upstream.handler = (_b, res) => json(res, 200, message());
      await send(history(issued));
      expect(upstream.calls).toHaveLength(2);
    }
  });

  it('runs the credential and PII patterns on the raw value even when it was issued', async () => {
    const { send } = setup();
    const withId = 'AAA+784199012345671/'; // canonical base64 holding an Emirates ID
    upstream.handler = (_b, res) =>
      json(
        res,
        200,
        message([{ type: 'thinking', thinking: 'x', signature: withId }]),
      );
    await send(request());
    await refused(send(history(withId)), 403, 'dlp_policy_violation');
    expect(upstream.calls).toHaveLength(1);
  });

  it('scans thinking-shaped objects anywhere but directly in assistant content, and malformed or oversized signatures', async () => {
    const { send } = setup();
    const nested = {
      type: 'thinking',
      thinking: 'x',
      signature: '784-1990-1234567-1',
    };
    await send(
      request({
        messages: [
          {
            role: 'assistant',
            content: [
              {
                type: 'tool_use',
                id: 't1',
                name: 'Bash',
                input: { note: nested },
              },
              {
                type: 'thinking',
                thinking: 'y',
                signature: 'id 784-1990-1234567-1',
              },
            ],
          },
          {
            role: 'user',
            content: [
              { type: 'tool_result', tool_use_id: 't1', content: [nested] },
            ],
          },
        ],
      }),
    );
    const sent = JSON.stringify(upstream.calls[0]!.body);
    expect(sent).not.toContain('784-1990-1234567-1');
    expect(sent.match(/\[REDACTED:EMIRATES_ID\]/g)).toHaveLength(3);
    // Over 8 KiB: not treated as a signature, scanned like any text (a JWT inside blocks).
    await refused(
      send(history(`${'A'.repeat(9000)} ${JWT}`)),
      403,
      'dlp_policy_violation',
    );
  });
});

describe('LlmAnthropicService: non-streaming pass-through', () => {
  it('sends the DLP-scanned body with the server key; budget and audit from usage', async () => {
    const { send, budget, audited, llmGate } = setup();
    const result = await send(
      request({
        system: [
          { type: 'text', text: 'Owner Emirates ID 784-1990-1234567-1.' },
        ],
        context_management: { edits: [] },
        metadata: { user_id: 'card 4111 1111 1111 1111' },
      }),
      { version: '2023-06-01' },
    );
    expect(result).toEqual({ json: message() });
    const call = upstream.calls[0]!;
    expect(call.path).toBe('/v1/messages');
    expect(call.headers['x-api-key']).toBe(SERVER_KEY);
    expect(call.headers.authorization).toBeUndefined();
    expect(call.body.model).toBe('claude-test');
    expect(call.body.context_management).toEqual({ edits: [] });
    expect(JSON.stringify(call.body.system)).toContain(
      '[REDACTED:EMIRATES_ID]',
    );
    expect(call.body.metadata).toEqual({
      user_id: 'card [REDACTED:PAYMENT_CARD]',
    });
    expect(llmGate).toHaveBeenCalledWith('tenant-1', 'llm_proxy', {
      external: true,
      uaeResident: false,
      model: 'claude-test',
    });
    expect(budget.add).toHaveBeenCalledWith(
      'tenant-1',
      'task-1',
      145,
      expect.any(Date),
    );
    expect(audited()[0]).toMatchObject({
      taskId: 'task-1',
      outcome: 'SUCCESS',
      format: 'anthropic',
      stream: false,
      provider: 'anthropic',
      model: 'claude-test',
      cacheCreationTokens: 5,
      cacheReadTokens: 100,
      totalTokens: 145,
    });
    expect(JSON.stringify(audited())).not.toContain('Owner Emirates');
  });

  it('DLP before the call: a credential in a tool result blocks, nothing is sent', async () => {
    await refused(
      setup().send(
        request({
          messages: [
            {
              role: 'user',
              content: [
                {
                  type: 'tool_result',
                  tool_use_id: 't1',
                  content: `token: ${JWT}`,
                },
              ],
            },
          ],
        }),
      ),
      403,
      'dlp_policy_violation',
    );
    expect(upstream.calls).toHaveLength(0);
  });

  it('DLP after the call: PII redacted; a credential, also one split between text and tool input, is refused after charging', async () => {
    const { send, budget, audited } = setup();
    upstream.handler = (_b, res) =>
      json(
        res,
        200,
        message([
          { type: 'text', text: 'Card 4111 1111 1111 1111 on file.' },
          {
            type: 'tool_use',
            id: 'toolu_1',
            name: 'Bash',
            input: { command: 'echo 784-1990-1234567-1' },
          },
        ]),
      );
    const ok = (await send(request())) as { json: Json };
    expect(ok.json.content).toEqual([
      { type: 'text', text: 'Card [REDACTED:PAYMENT_CARD] on file.' },
      {
        type: 'tool_use',
        id: 'toolu_1',
        name: 'Bash',
        input: { command: 'echo [REDACTED:EMIRATES_ID]' },
      },
    ]);
    upstream.handler = (_b, res) =>
      json(
        res,
        200,
        message([
          { type: 'text', text: `Use ${JWT.slice(0, 30)}` },
          {
            type: 'tool_use',
            id: 't',
            name: 'Bash',
            input: { command: JWT.slice(30) },
          },
        ]),
      );
    await refused(send(request()), 403, 'dlp_policy_violation');
    expect(budget.add).toHaveBeenCalledTimes(2);
    expect(audited().at(-1)).toMatchObject({
      outcome: 'DENIED',
      reason: 'dlp_policy_violation',
      responseDlp: { credentialTypes: ['jwt'] },
    });
  });

  it("passes the upstream's own 400 error through; a 500 is 502", async () => {
    const { send } = setup();
    upstream.handler = (_b, res) =>
      json(res, 400, {
        type: 'error',
        error: {
          type: 'invalid_request_error',
          message: 'context_management: Extra inputs are not permitted',
        },
      });
    await expect(send(request())).rejects.toMatchObject({
      status: 400,
      response: {
        error: {
          message: 'context_management: Extra inputs are not permitted',
        },
        reason: 'llm_upstream_rejected',
      },
    });
    upstream.handler = (_b, res) =>
      json(res, 500, {
        type: 'error',
        error: { type: 'api_error', message: 'x' },
      });
    await refused(send(request()), 502, 'llm_upstream_unavailable');
  });

  it('a client that leaves during a call is charged and recorded (non-streaming and before stream headers)', async () => {
    for (const stream of [false, true]) {
      const { send, audited, budget } = setup();
      upstream.handler = (_b, res) =>
        void setTimeout(() => json(res, 200, message()), 2_000);
      const leave = new AbortController();
      const reply = send(request({ stream }), {}, leave.signal);
      await vi.waitFor(() => expect(upstream.calls.length).toBeGreaterThan(0));
      leave.abort();
      await expect(reply).rejects.toBeDefined();
      expect(audited()).toHaveLength(1);
      expect(audited()[0]).toMatchObject({
        outcome: 'INCOMPLETE',
        reason: 'client_closed',
      });
      expect(budget.add).toHaveBeenCalledTimes(1);
      upstream.calls = [];
    }
  });
});

const textOf = (events: SseEvent[]) =>
  events
    .filter((e) => e.data.type === 'content_block_delta')
    .map((e) => ((e.data.delta as Json).text as string | undefined) ?? '')
    .join('');

/** Upstream events for one text block made of `deltas`, then a tool call with `input`. */
function withTool(deltas: string[], input: string): string[] {
  const all = streamEvents(deltas);
  return [
    ...all.slice(0, -3),
    sseText('content_block_start', {
      index: 1,
      content_block: { type: 'tool_use', id: 't', name: 'Bash', input: {} },
    }),
    sseText('content_block_delta', {
      index: 1,
      delta: { type: 'input_json_delta', partial_json: input },
    }),
    sseText('content_block_stop', { index: 1 }),
    ...all.slice(-2),
  ];
}

describe.each(['buffer', 'incremental'])(
  'LlmAnthropicService: streaming, %s mode',
  (mode) => {
    const env = { LLM_ANTHROPIC_STREAM_DLP: mode };
    const filler = 'x '.repeat(400);

    it('streams the answer, charges the reported usage, and releases message_stop after the audit', async () => {
      const { send, budget, audit } = setup({ env });
      upstream.handler = streamFrom(streamEvents(['Hello ', 'world.']));
      let auditedBeforeDelta = false;
      const events = await collect(
        await send(request({ stream: true })),
        (e) => {
          if (e.data.type === 'message_delta')
            auditedBeforeDelta = audit.record.mock.calls.length === 1;
        },
      );
      const types = events.map((e) => e.data.type).filter((t) => t !== 'ping');
      expect(types).toEqual([
        'message_start',
        'content_block_start',
        'content_block_delta',
        'content_block_stop',
        'message_delta',
        'message_stop',
      ]);
      expect(textOf(events)).toBe('Hello world.');
      expect(auditedBeforeDelta).toBe(true);
      // 30 input + 7 output (cumulative, from message_delta) + 100 cache read.
      expect(budget.add).toHaveBeenCalledWith(
        'tenant-1',
        'task-1',
        137,
        expect.any(Date),
      );
    });

    it('redacts PII split across deltas and PII lying across the release point', async () => {
      const { send, audited } = setup({ env });
      upstream.handler = streamFrom(
        streamEvents(['ID 784-1990-', '1234567-1 ok']),
      );
      expect(textOf(await collect(await send(request({ stream: true }))))).toBe(
        'ID [REDACTED:EMIRATES_ID] ok',
      );
      expect(audited().at(-1)).toMatchObject({
        responseDlp: { piiTypes: ['emirates_id'] },
      });
      // The lookahead cut (end - 512) would fall inside the card.
      upstream.handler = streamFrom(
        streamEvents([
          'x'.repeat(1000) + ' 4111 1111 1111 1111 ' + 'b'.repeat(500),
        ]),
      );
      const out = textOf(await collect(await send(request({ stream: true }))));
      expect(out).not.toMatch(/4111|1111/);
      expect(out).toContain('[REDACTED:PAYMENT_CARD]');
    });

    it.each([
      [
        'a JWT split across deltas',
        [
          filler,
          'Your token is ',
          JWT.slice(0, 20),
          JWT.slice(20, 40),
          JWT.slice(40),
          ' bye',
        ],
        JWT.slice(0, 12),
      ],
      [
        'a bearer token split across deltas',
        [
          filler,
          'Authorization: Bearer ',
          'AbCdEfGhIjKlMnOp',
          'QrStUvWxYz0123456789',
          ' end',
        ],
        'AbCdEfGh',
      ],
      [
        'a bearer token after 600 spaces',
        [
          filler,
          'Authorization: Bearer',
          ' '.repeat(600),
          'AbCdEfGhIjKlMnOpQrStUvWx',
          ' end',
        ],
        'AbCdEfGh',
      ],
      [
        'an AccountKey after padding',
        [
          filler,
          'AccountKey',
          ' '.repeat(600),
          '=',
          'Zm9vYmFyYmF6cXV4cXV1eA',
          ';x',
        ],
        'Zm9vYmFy',
      ],
      [
        'a 600-character password value',
        [filler, '{"password": "', 'p@'.repeat(300), '"}'],
        'p@p@p@',
      ],
    ])(
      'blocks %s before any of it is released',
      async (_name, parts, secret) => {
        const { send, audited, budget } = setup({ env });
        upstream.handler = streamFrom(streamEvents(parts));
        const events = await collect(await send(request({ stream: true })));
        expect(events.at(-1)!.data).toMatchObject({
          type: 'error',
          error: { type: 'permission_error', message: 'dlp_policy_violation' },
          reason: 'dlp_policy_violation',
        });
        expect(events.map((e) => e.data.type)).not.toContain('message_stop');
        expect(JSON.stringify(events)).not.toContain(secret);
        expect(audited().at(-1)).toMatchObject({
          outcome: 'DENIED',
          reason: 'dlp_policy_violation',
          stream: true,
        });
        expect(budget.add).toHaveBeenCalledTimes(1);
      },
    );

    it('blocks a credential split between text and tool input, and one in a citation', async () => {
      const { send } = setup({ env });
      upstream.handler = streamFrom(
        withTool([filler, 'see ' + JWT.slice(0, 30)], JWT.slice(30)),
      );
      let events = await collect(await send(request({ stream: true })));
      expect(events.at(-1)!.data).toMatchObject({
        reason: 'dlp_policy_violation',
      });
      expect(JSON.stringify(events)).not.toContain(JWT.slice(0, 12));

      const all = streamEvents(['Quoted.']);
      upstream.handler = streamFrom([
        ...all.slice(0, 3),
        sseText('content_block_delta', {
          index: 0,
          delta: {
            type: 'citations_delta',
            citation: { type: 'char_location', cited_text: `key ${JWT}` },
          },
        }),
        ...all.slice(3),
      ]);
      events = await collect(await send(request({ stream: true })));
      expect(events.at(-1)!.data).toMatchObject({
        reason: 'dlp_policy_violation',
      });
    });

    it('holds a tool call input and releases it redacted', async () => {
      const { send } = setup({ env });
      const input = '{"command": "echo 784-1990-1234567-1"}';
      upstream.handler = streamFrom(withTool(['Running.'], input));
      const events = await collect(await send(request({ stream: true })));
      const json = events
        .filter(
          (e) =>
            (e.data.delta as Json | undefined)?.type === 'input_json_delta',
        )
        .map((e) => (e.data.delta as Json).partial_json as string)
        .join('');
      expect(JSON.parse(json)).toEqual({
        command: 'echo [REDACTED:EMIRATES_ID]',
      });
    });

    it('charges a stream the client left by the larger of reported usage and input plus output seen', async () => {
      const { send, audited, budget } = setup({ env });
      let release!: () => void;
      const hold = new Promise<void>((r) => (release = r));
      const all = streamEvents(['y '.repeat(2000)]); // 4000 output chars
      // start, block start, the delta, then a ping; the rest waits.
      upstream.handler = streamFrom(
        [[all[0], all[1], all[3], all[2]].join(''), ...all.slice(4)],
        hold,
      );
      const leave = new AbortController();
      const reply = (await send(
        request({ stream: true }),
        {},
        leave.signal,
      )) as {
        stream: AsyncGenerator<string>;
      };
      if (mode === 'incremental') {
        for (;;) {
          const r = await reply.stream.next();
          if (r.done || String(r.value).includes('event: ping')) break;
        }
      } else {
        void reply.stream.next();
        await new Promise((r) => setTimeout(r, 200));
      }
      leave.abort();
      await reply.stream.return(undefined);
      release();
      await vi.waitFor(() =>
        expect(audited().at(-1)).toMatchObject({
          outcome: 'INCOMPLETE',
          reason: 'client_closed',
        }),
      );
      // Reported 131 (30 in + 1 out + 100 cache) is less than input 130 + output seen / 4.
      expect(budget.add.mock.calls[0]![2]).toBeGreaterThanOrEqual(1130);
    });

    it('cuts at the overall deadline while the upstream keeps the stream alive', async () => {
      const { send, audited } = setup({
        env: { ...env, LLM_STREAM_MAX_MS: 300 },
      });
      let stop = false;
      upstream.handler = async (_b, res) => {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write(streamEvents([])[0]);
        while (!stop && !res.destroyed) {
          res.write(sseText('ping', {}));
          await new Promise((r) => setTimeout(r, 50));
        }
        res.end();
      };
      const events = await collect(await send(request({ stream: true })));
      stop = true;
      expect(events.at(-1)!.data).toMatchObject({
        type: 'error',
        reason: 'llm_upstream_unavailable',
      });
      expect(audited().at(-1)).toMatchObject({
        outcome: 'UPSTREAM_ERROR',
        reason: 'stream_deadline',
      });
    });

    it('tears down a stream whose client stopped reading, then charges and records it', async () => {
      const { send, audited, budget } = setup({
        env: { ...env, LLM_STREAM_MAX_MS: 400 },
      });
      let stop = false;
      upstream.handler = async (_b, res) => {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write(streamEvents([])[0]);
        while (!stop && !res.destroyed) {
          res.write(sseText('ping', {}));
          await new Promise((r) => setTimeout(r, 5));
        }
        res.end();
      };
      const readable = replyStream(
        (await send(request({ stream: true }))) as {
          stream: AsyncGenerator<string>;
          stop?: AbortSignal;
        },
      );
      readable.once('data', () => readable.pause()); // reads one chunk, then never again
      await vi.waitFor(() => expect(audited()).toHaveLength(1), {
        timeout: 3_000,
      });
      stop = true;
      expect(['UPSTREAM_ERROR', 'INCOMPLETE']).toContain(audited()[0]!.outcome);
      expect(budget.add).toHaveBeenCalledTimes(1);
    });
  },
);

describe('AnthropicStreamGuard (incremental): cost', () => {
  it('releases long plain text before the message ends', () => {
    const guard = new AnthropicStreamGuard();
    guard.push({
      event: 'content_block_start',
      data: {
        type: 'content_block_start',
        index: 0,
        content_block: { type: 'text', text: '' },
      },
    });
    let early = '';
    for (let i = 0; i < 100; i++) {
      for (const e of guard.push({
        event: 'content_block_delta',
        data: {
          type: 'content_block_delta',
          index: 0,
          delta: { type: 'text_delta', text: 'lorem ipsum dolor ' },
        },
      }))
        early += str((e.data.delta as Json | undefined)?.text);
    }
    expect(early.length).toBeGreaterThan(1000);
    expect(early.length).toBeLessThanOrEqual(1800 - 512);
  });

  it('scans a long token-like stream in small deltas in linear time', () => {
    const guard = new AnthropicStreamGuard();
    const alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let blob = '';
    for (let i = 0; i < 100_000; i++)
      blob += alphabet[(i * 7919 + (i >> 5)) % 64];
    const t0 = performance.now();
    guard.push({
      event: 'message_start',
      data: { type: 'message_start', message: {} },
    });
    guard.push({
      event: 'content_block_start',
      data: {
        type: 'content_block_start',
        index: 0,
        content_block: { type: 'text', text: '' },
      },
    });
    let out = '';
    for (let i = 0; i < blob.length; i += 8) {
      for (const e of guard.push({
        event: 'content_block_delta',
        data: {
          type: 'content_block_delta',
          index: 0,
          delta: { type: 'text_delta', text: blob.slice(i, i + 8) },
        },
      }))
        out += str((e.data.delta as Json | undefined)?.text);
    }
    for (const e of guard.push({
      event: 'message_stop',
      data: { type: 'message_stop' },
    }))
      out += str((e.data.delta as Json | undefined)?.text);
    expect(out).toBe(blob);
    expect(performance.now() - t0).toBeLessThan(3_000);
  });
});

describe('LlmAnthropicService: openai_translate', () => {
  const env = { LLM_ANTHROPIC_PROVIDER: 'openai_translate' };
  const completion = {
    id: 'chatcmpl-9',
    object: 'chat.completion',
    model: 'fixture-model',
    choices: [
      {
        index: 0,
        finish_reason: 'tool_calls',
        message: {
          role: 'assistant',
          content: 'Checking.',
          tool_calls: [
            {
              id: 'call_2',
              type: 'function',
              function: { name: 'Bash', arguments: '{"command":"ls"}' },
            },
          ],
        },
      },
    ],
    usage: { prompt_tokens: 50, completion_tokens: 12, total_tokens: 62 },
  };
  const withToolCall = (_b: Json, res: ServerResponse) =>
    json(res, 200, completion);
  const conversation = request({
    system: 'You are a coding agent.',
    tools: [
      {
        name: 'Bash',
        description: 'Run a command',
        input_schema: {
          type: 'object',
          properties: { command: { type: 'string' } },
        },
      },
    ],
    tool_choice: { type: 'auto' },
    messages: [
      { role: 'user', content: 'List the files.' },
      {
        role: 'assistant',
        content: [
          {
            type: 'tool_use',
            id: 'call_1',
            name: 'Bash',
            input: { command: 'pwd' },
          },
        ],
      },
      {
        role: 'user',
        content: [
          { type: 'tool_result', tool_use_id: 'call_1', content: '/repo' },
        ],
      },
    ],
  });

  it('round-trips a tool call: Anthropic request -> OpenAI upstream -> Anthropic message', async () => {
    const { send, llmGate, budget, audited } = setup({ env });
    upstream.handler = withToolCall;
    const { json: reply } = (await send(conversation)) as { json: Json };
    const call = upstream.calls[0]!;
    expect(call.path).toBe('/v1/chat/completions');
    expect(call.body).toMatchObject({
      model: 'fixture-model',
      max_tokens: 1024,
      tool_choice: 'auto',
      tools: [
        {
          type: 'function',
          function: {
            name: 'Bash',
            description: 'Run a command',
            parameters: { type: 'object' },
          },
        },
      ],
      messages: [
        { role: 'system', content: 'You are a coding agent.' },
        { role: 'user', content: 'List the files.' },
        {
          role: 'assistant',
          content: null,
          tool_calls: [
            {
              id: 'call_1',
              type: 'function',
              function: { name: 'Bash', arguments: '{"command":"pwd"}' },
            },
          ],
        },
        { role: 'tool', tool_call_id: 'call_1', content: '/repo' },
      ],
    });
    expect(llmGate).toHaveBeenCalledWith('tenant-1', 'llm_proxy', undefined);
    expect(reply).toMatchObject({
      type: 'message',
      model: 'fixture-model',
      stop_reason: 'tool_use',
      content: [
        { type: 'text', text: 'Checking.' },
        {
          type: 'tool_use',
          id: 'call_2',
          name: 'Bash',
          input: { command: 'ls' },
        },
      ],
      usage: { input_tokens: 50, output_tokens: 12 },
    });
    expect(budget.add).toHaveBeenCalledWith(
      'tenant-1',
      'task-1',
      62,
      expect.any(Date),
    );
    expect(audited()).toHaveLength(1);
    expect(audited()[0]).toMatchObject({
      outcome: 'SUCCESS',
      provider: 'ollama',
    });
  });

  it('streams the translated message as Anthropic events', async () => {
    const { send } = setup({ env });
    upstream.handler = withToolCall;
    const events = await collect(await send({ ...conversation, stream: true }));
    expect(events.map((e) => e.data.type)).toEqual([
      'message_start',
      'content_block_start',
      'content_block_delta',
      'content_block_stop',
      'content_block_start',
      'content_block_delta',
      'content_block_stop',
      'message_delta',
      'message_stop',
    ]);
    expect(events[5]!.data.delta).toEqual({
      type: 'input_json_delta',
      partial_json: '{"command":"ls"}',
    });
  });

  it('charges and audits a streamed call the client never read', async () => {
    const { send, audited, budget } = setup({ env });
    upstream.handler = withToolCall;
    await send({ ...conversation, stream: true });
    await vi.waitFor(() => expect(audited()).toHaveLength(1));
    expect(audited()[0]).toMatchObject({ outcome: 'SUCCESS', totalTokens: 62 });
    expect(budget.add).toHaveBeenCalledWith(
      'tenant-1',
      'task-1',
      62,
      expect.any(Date),
    );
  });

  it('a client that leaves aborts the upstream call, and the call is still charged and recorded once', async () => {
    const { send, audited, budget } = setup({ env });
    let upstreamClosed = false;
    upstream.handler = (_b, res) => {
      res.on('close', () => (upstreamClosed = true));
      setTimeout(() => json(res, 200, completion), 2_000);
    };
    const leave = new AbortController();
    await send({ ...conversation, stream: true }, {}, leave.signal);
    await vi.waitFor(() => expect(upstream.calls).toHaveLength(1));
    leave.abort();
    await vi.waitFor(() => expect(audited()).toHaveLength(1));
    expect(audited()[0]).toMatchObject({
      outcome: 'INCOMPLETE',
      reason: 'client_closed',
    });
    expect(budget.add).toHaveBeenCalledTimes(1);
    await vi.waitFor(() => expect(upstreamClosed).toBe(true));
    await new Promise((r) => setTimeout(r, 50));
    expect(audited()).toHaveLength(1);
  });

  it('a failed upstream ends the stream with an error event (502 reason), recorded once', async () => {
    const { send, audited } = setup({ env });
    upstream.handler = (_b, res) => json(res, 500, {});
    const events = await collect(await send({ ...conversation, stream: true }));
    expect(events.map((e) => e.data)).toEqual([
      {
        type: 'error',
        error: { type: 'api_error', message: 'llm_upstream_unavailable' },
        reason: 'llm_upstream_unavailable',
      },
    ]);
    expect(audited()).toHaveLength(1);
    expect(audited()[0]).toMatchObject({
      outcome: 'UPSTREAM_ERROR',
      reason: 'HTTP 500',
    });
  });
});

describe('LlmAnthropicService.models', () => {
  it('lists the OpenAI-format model and the Anthropic models in a shape both clients read', async () => {
    const { service } = setup();
    expect(await service.models(AGENT)).toEqual({
      object: 'list',
      data: ['fixture-model', 'claude-test', 'claude-small'].map((id) => ({
        id,
        object: 'model',
        type: 'model',
        created: 0,
        created_at: '1970-01-01T00:00:00Z',
        display_name: id,
        owned_by: 'manar',
      })),
      has_more: false,
      first_id: 'fixture-model',
      last_id: 'claude-small',
    });
    const none = await setup({
      env: { LLM_ANTHROPIC_MODELS: '' },
    }).service.models(AGENT);
    expect((none.data as Json[]).map((m) => m.id)).toEqual(['fixture-model']);
  });
});

describe('anthropicError', () => {
  it("keeps Manar's decision and reason next to the Anthropic error type", () => {
    expect(
      anthropicError(
        new HttpException(
          { decision: 'DENY', reason: 'llm_budget_exhausted' },
          429,
        ),
      ),
    ).toEqual({
      status: 429,
      body: {
        type: 'error',
        error: { type: 'rate_limit_error', message: 'llm_budget_exhausted' },
        decision: 'DENY',
        reason: 'llm_budget_exhausted',
      },
    });
  });
});

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
