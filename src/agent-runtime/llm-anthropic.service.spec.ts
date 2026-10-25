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
import { anthropicError, parseSse, type SseEvent } from './llm-anthropic';
import {
  LlmAnthropicService,
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
  const budget = {
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
    LLM_PROVIDER: 'ollama',
    LLM_MODEL: 'fixture-model',
    LLM_OLLAMA_BASE_URL: `${upstream.url}/v1`,
    LLM_ANTHROPIC_PROVIDER: 'anthropic',
    LLM_ANTHROPIC_BASE_URL: upstream.url,
    ANTHROPIC_API_KEY: SERVER_KEY,
    LLM_ANTHROPIC_MODELS: '',
    LLM_ANTHROPIC_UAE_RESIDENT: 'false',
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
  const service = new LlmAnthropicService(proxy, client, config, catalog);
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

describe('LlmAnthropicService: providers and request policy', () => {
  it('is 404 anthropic_disabled for provider none, and for anthropic without a key', async () => {
    await refused(
      setup({ env: { LLM_ANTHROPIC_PROVIDER: 'none' } }).send(request()),
      404,
      'anthropic_disabled',
    );
    await refused(
      setup({ env: { ANTHROPIC_API_KEY: undefined } }).send(request()),
      404,
      'anthropic_disabled',
    );
    expect(upstream.calls).toHaveLength(0);
  });

  it('task gate DENY: a killed agent never reaches the upstream, and the refusal is audited', async () => {
    const { send, audited } = setup({ killed: 'agent_killed' });
    await refused(send(request()), 403, 'agent_killed');
    expect(upstream.calls).toHaveLength(0);
    expect(audited()[0]).toMatchObject({
      outcome: 'DENIED',
      reason: 'agent_killed',
      format: 'anthropic',
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

  it('refuses server tools in the wording Claude Code retries on, and content DLP cannot read', async () => {
    const { send } = setup();
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
    const image = {
      type: 'image',
      source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0KGgo=' },
    };
    await refused(
      send(
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
});

describe('LlmAnthropicService: non-streaming pass-through', () => {
  it('sends the DLP-scanned body with the server key and only the allow-listed client headers', async () => {
    const { send, budget, audited, llmGate } = setup({
      env: { LLM_ANTHROPIC_MODELS: 'claude-main, claude-small' },
    });
    const thinking = {
      type: 'thinking',
      thinking: 'Plan.',
      signature: 'c2ln+784199012345671/',
    };
    const result = await send(
      request({
        model: 'claude-unknown',
        system: [
          { type: 'text', text: 'Owner Emirates ID 784-1990-1234567-1.' },
        ],
        messages: [
          { role: 'user', content: 'Hi' },
          {
            role: 'assistant',
            content: [thinking, { type: 'text', text: 'Hello' }],
          },
          { role: 'user', content: 'Go on' },
        ],
        context_management: { edits: [] },
      }),
      { version: '2023-06-01', beta: 'interleaved-thinking-2025-05-14' },
    );
    expect(result).toEqual({ json: message() });

    const call = upstream.calls[0]!;
    expect(call.path).toBe('/v1/messages');
    expect(call.headers['x-api-key']).toBe(SERVER_KEY);
    expect(call.headers['anthropic-version']).toBe('2023-06-01');
    expect(call.headers['anthropic-beta']).toBe(
      'interleaved-thinking-2025-05-14',
    );
    expect(call.headers.authorization).toBeUndefined();
    // Unknown model -> the install's default; other fields pass through.
    expect(call.body.model).toBe('claude-main');
    expect(call.body.context_management).toEqual({ edits: [] });
    expect(JSON.stringify(call.body.system)).toContain(
      '[REDACTED:EMIRATES_ID]',
    );
    // The thinking signature reaches the upstream unchanged (not scanned, not redacted).
    expect((call.body.messages as Json[])[1]).toEqual({
      role: 'assistant',
      content: [thinking, { type: 'text', text: 'Hello' }],
    });

    expect(llmGate).toHaveBeenCalledWith('tenant-1', 'llm_proxy', {
      external: true,
      uaeResident: false,
    });
    // Budget from usage: input + output + cache creation + cache read.
    expect(budget.add).toHaveBeenCalledWith(
      'tenant-1',
      'task-1',
      145,
      expect.any(Date),
    );
    expect(audited()[0]).toMatchObject({
      outcome: 'SUCCESS',
      format: 'anthropic',
      stream: false,
      provider: 'anthropic',
      model: 'claude-main',
      promptTokens: 30,
      completionTokens: 10,
      cacheCreationTokens: 5,
      cacheReadTokens: 100,
      totalTokens: 145,
      dlp: { floorRedactedPiiTypes: ['emirates_id'] },
    });
    expect(JSON.stringify(audited())).not.toContain('Owner Emirates');
  });

  it('DLP before the call: a credential in a tool result blocks, nothing is sent', async () => {
    const { send } = setup();
    await refused(
      send(
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

  it('DLP after the call: PII in text and tool input is redacted; a credential is refused after charging', async () => {
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
    expect(JSON.stringify(ok.json)).not.toMatch(/4111 1111|784-1990/);
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
      json(res, 200, message([{ type: 'text', text: `Use ${JWT}` }]));
    await refused(send(request()), 403, 'dlp_policy_violation');
    expect(budget.add).toHaveBeenCalledTimes(2);
    expect(audited().at(-1)).toMatchObject({
      outcome: 'DENIED',
      reason: 'dlp_policy_violation',
      responseDlp: { credentialTypes: ['jwt'] },
    });
  });

  it("passes the upstream's own 400 error through (Claude Code adapts to it); a 500 is 502", async () => {
    const { send } = setup();
    upstream.handler = (_b, res) =>
      json(res, 400, {
        type: 'error',
        error: {
          type: 'invalid_request_error',
          message: 'context_management: Extra inputs are not permitted',
        },
      });
    const rejected = send(request());
    await expect(rejected).rejects.toMatchObject({
      status: 400,
      response: {
        type: 'error',
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
});

describe('LlmAnthropicService: streaming pass-through', () => {
  it('relays events as they arrive, charges the reported usage, and releases message_stop after the audit', async () => {
    const { send, budget, audit } = setup();
    let release!: () => void;
    const hold = new Promise<void>((r) => (release = r));
    upstream.handler = streamFrom(streamEvents(['Hello ', 'world.']), hold);

    const reply = await send(request({ stream: true }));
    const seen: string[] = [];
    let auditedBeforeDelta = false;
    const events = await collect(reply, (e) => {
      seen.push(e.data.type as string);
      // The first event is out while the upstream is still holding the rest.
      if (seen.length === 1) release();
      if (e.data.type === 'message_delta')
        auditedBeforeDelta = audit.record.mock.calls.length === 1;
    });
    expect(seen).toEqual([
      'message_start',
      'content_block_start',
      'ping',
      'content_block_delta',
      'content_block_delta',
      'content_block_stop',
      'message_delta',
      'message_stop',
    ]);
    const text = events
      .filter((e) => e.data.type === 'content_block_delta')
      .map((e) => (e.data.delta as Json).text)
      .join('');
    expect(text).toBe('Hello world.');
    expect(auditedBeforeDelta).toBe(true);
    // 30 input + 7 output (cumulative, from message_delta) + 100 cache read.
    expect(budget.add).toHaveBeenCalledWith(
      'tenant-1',
      'task-1',
      137,
      expect.any(Date),
    );
    expect(
      (audit.record.mock.calls[0]![2] as { data: Json }).data,
    ).toMatchObject({
      outcome: 'SUCCESS',
      stream: true,
      totalTokens: 137,
    });
  });

  it('redacts PII split across deltas, and cuts the stream with an error event on a credential', async () => {
    const { send, audited, budget } = setup();
    upstream.handler = streamFrom(
      streamEvents(['ID 784-1990-', '1234567-1 ok']),
    );
    const events = await collect(await send(request({ stream: true })));
    const text = events
      .filter((e) => e.data.type === 'content_block_delta')
      .map((e) => (e.data.delta as Json).text)
      .join('');
    expect(text).toBe('ID [REDACTED:EMIRATES_ID] ok');
    expect(audited().at(-1)).toMatchObject({
      responseDlp: { piiTypes: ['emirates_id'] },
    });

    upstream.handler = streamFrom(
      streamEvents(['Your token is ', JWT.slice(0, 20), JWT.slice(20), ' bye']),
    );
    const cut = await collect(await send(request({ stream: true })));
    const types = cut.map((e) => e.data.type);
    expect(types.at(-1)).toBe('error');
    expect(types).not.toContain('message_stop');
    expect(cut.at(-1)!.data).toMatchObject({
      type: 'error',
      error: { type: 'permission_error', message: 'dlp_policy_violation' },
      reason: 'dlp_policy_violation',
    });
    expect(JSON.stringify(cut)).not.toContain(JWT);
    expect(audited().at(-1)).toMatchObject({
      outcome: 'DENIED',
      reason: 'dlp_policy_violation',
      stream: true,
      responseDlp: { credentialTypes: ['jwt'] },
    });
    expect(budget.add).toHaveBeenCalledTimes(2);
  });

  it('records a stream the client left as INCOMPLETE, and still charges what it used', async () => {
    const { send, audited, budget } = setup();
    let release!: () => void;
    const hold = new Promise<void>((r) => (release = r));
    upstream.handler = streamFrom(streamEvents(['partial']), hold);
    const reply = (await send(request({ stream: true }))) as {
      stream: AsyncGenerator<string>;
    };
    await reply.stream.next();
    await reply.stream.return(undefined);
    release();
    expect(audited().at(-1)).toMatchObject({
      outcome: 'INCOMPLETE',
      reason: 'client_closed',
    });
    expect(budget.add).toHaveBeenCalledWith(
      'tenant-1',
      'task-1',
      131,
      expect.any(Date),
    );
  });

  it('holds a tool call input whole and releases it redacted at the block end', async () => {
    const { send } = setup();
    const json = '{"command": "echo 784-1990-1234567-1"}';
    upstream.handler = streamFrom([
      sseText('message_start', { message: message([]) }),
      sseText('content_block_start', {
        index: 0,
        content_block: {
          type: 'tool_use',
          id: 'toolu_1',
          name: 'Bash',
          input: {},
        },
      }),
      sseText('content_block_delta', {
        index: 0,
        delta: { type: 'input_json_delta', partial_json: json.slice(0, 25) },
      }),
      sseText('content_block_delta', {
        index: 0,
        delta: { type: 'input_json_delta', partial_json: json.slice(25) },
      }),
      sseText('content_block_stop', { index: 0 }),
      sseText('message_delta', {
        delta: { stop_reason: 'tool_use' },
        usage: { output_tokens: 9 },
      }),
      sseText('message_stop', {}),
    ]);
    const events = await collect(await send(request({ stream: true })));
    const deltas = events.filter((e) => e.data.type === 'content_block_delta');
    expect(deltas).toHaveLength(1);
    expect(
      JSON.parse((deltas[0]!.data.delta as Json).partial_json as string),
    ).toEqual({
      command: 'echo [REDACTED:EMIRATES_ID]',
    });
  });
});

describe('LlmAnthropicService: openai_translate', () => {
  const env = { LLM_ANTHROPIC_PROVIDER: 'openai_translate' };
  const withToolCall = (_b: Json, res: ServerResponse) =>
    json(res, 200, {
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
    });
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
    // Residency follows the OpenAI-format upstream: the catalog judges it, no fixed placement.
    expect(llmGate).toHaveBeenCalledWith('tenant-1', 'llm_proxy', undefined);

    expect(reply).toMatchObject({
      type: 'message',
      role: 'assistant',
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
    expect(audited()[0]).toMatchObject({
      outcome: 'SUCCESS',
      provider: 'ollama',
      model: 'fixture-model',
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
    expect(events[7]!.data).toMatchObject({
      delta: { stop_reason: 'tool_use' },
      usage: { output_tokens: 12 },
    });
  });

  it('a failed upstream ends the stream with an error event (502 reason)', async () => {
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
    expect(audited().at(-1)).toMatchObject({
      outcome: 'UPSTREAM_ERROR',
      reason: 'HTTP 500',
    });
  });
});

describe('LlmAnthropicService.models', () => {
  it('lists the OpenAI-format model and the Anthropic models in a shape both clients read', async () => {
    const { service } = setup({
      env: { LLM_ANTHROPIC_MODELS: 'claude-main,claude-small' },
    });
    expect(await service.models(AGENT)).toEqual({
      object: 'list',
      data: ['fixture-model', 'claude-main', 'claude-small'].map((id) => ({
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
      env: {
        LLM_ANTHROPIC_PROVIDER: 'none',
        LLM_ANTHROPIC_MODELS: 'claude-main',
      },
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
    expect(
      anthropicError(
        new HttpException('X-Manar-Task-Id header is required', 400),
      ).body,
    ).toEqual({
      type: 'error',
      error: {
        type: 'invalid_request_error',
        message: 'X-Manar-Task-Id header is required',
      },
    });
  });
});
