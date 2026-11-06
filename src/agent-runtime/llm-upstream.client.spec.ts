import type { ConfigService } from '@nestjs/config';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import {
  forAzureReasoningModel,
  LlmUpstreamClient,
} from './llm-upstream.client';

const messages = [{ role: 'user', content: 'hi' }];

describe('forAzureReasoningModel', () => {
  it('sends max_completion_tokens and drops temperature', () => {
    const out = forAzureReasoningModel(
      { messages, max_tokens: 256, temperature: 0.2 },
      'gpt-5.4-mini',
    );
    expect(out).toEqual({ messages, max_completion_tokens: 256 });
  });

  it('maps none to minimal for the original GPT-5 deployments only', () => {
    for (const d of ['gpt-5', 'gpt-5-mini', 'gpt-5-nano']) {
      expect(
        forAzureReasoningModel({ messages, reasoning_effort: 'none' }, d)
          .reasoning_effort,
      ).toBe('minimal');
    }
    expect(
      forAzureReasoningModel(
        { messages, reasoning_effort: 'none' },
        'gpt-5.4-mini',
      ).reasoning_effort,
    ).toBe('none');
  });

  it('maps minimal to none for gpt-5.1 and later', () => {
    expect(
      forAzureReasoningModel(
        { messages, reasoning_effort: 'minimal' },
        'gpt-5.4-mini',
      ).reasoning_effort,
    ).toBe('none');
  });

  it('leaves other efforts and unknown deployment names alone', () => {
    expect(
      forAzureReasoningModel(
        { messages, reasoning_effort: 'low' },
        'gpt-5.4-mini',
      ).reasoning_effort,
    ).toBe('low');
    expect(
      forAzureReasoningModel({ messages, reasoning_effort: 'none' }, 'chat')
        .reasoning_effort,
    ).toBe('none');
  });
});

describe('LlmUpstreamClient.chat (azure_openai)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('posts the translated body to the deployment URL with the api-key header', async () => {
    const env: Record<string, unknown> = {
      LLM_PROVIDER: 'azure_openai',
      LLM_UPSTREAM_TIMEOUT_MS: 1000,
      LLM_AZURE_OPENAI_ENDPOINT: 'https://oai.example.openai.azure.com/',
      LLM_AZURE_OPENAI_DEPLOYMENT: 'gpt-5.4-mini',
      LLM_AZURE_OPENAI_API_VERSION: '2025-04-01-preview',
      AZURE_OPENAI_API_KEY: 'test-key',
    };
    const config = {
      get: (k: string) => env[k],
    } as unknown as ConfigService<AppConfig, true>;
    const fetchMock = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ choices: [{ message: {} }] }), {
          status: 200,
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await new LlmUpstreamClient(config).chat({
      messages,
      max_tokens: 100,
      temperature: 0,
      reasoning_effort: 'none',
    });

    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe(
      'https://oai.example.openai.azure.com/openai/deployments/gpt-5.4-mini/chat/completions?api-version=2025-04-01-preview',
    );
    expect((init.headers as Record<string, string>)['api-key']).toBe(
      'test-key',
    );
    expect(JSON.parse(init.body as string)).toEqual({
      messages,
      max_completion_tokens: 100,
      reasoning_effort: 'none',
      model: 'gpt-5.4-mini',
      stream: false,
    });
  });
});

describe('LlmUpstreamClient.chatStream', () => {
  const cfg = {
    get: (key: string) =>
      (
        ({
          LLM_PROVIDER: 'ollama',
          LLM_OLLAMA_BASE_URL: 'http://ollama.test/v1',
          LLM_MODEL: 'qwen3',
        }) as Record<string, unknown>
      )[key],
  } as unknown as ConfigService<AppConfig, true>;
  const limits = { firstTokenMs: 1000, idleMs: 1000, totalMs: 5000 };

  function sse(events: unknown[], pace?: () => Promise<void>): Response {
    const enc = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      async start(controller) {
        for (const e of events) {
          await pace?.();
          const text =
            e === '[DONE]'
              ? 'data: [DONE]\n\n'
              : `data: ${JSON.stringify(e)}\n\n`;
          // Split mid-line to prove the reader reassembles lines across chunks.
          controller.enqueue(enc.encode(text.slice(0, 7)));
          controller.enqueue(enc.encode(text.slice(7)));
        }
        controller.close();
      },
    });
    return new Response(body, { status: 200 });
  }

  afterEach(() => vi.unstubAllGlobals());

  it('hands over text as it arrives and assembles content, tool calls and usage', async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(
        sse([
          { model: 'qwen3', choices: [{ delta: { content: 'Hel' } }] },
          { choices: [{ delta: { content: 'lo' } }] },
          {
            choices: [
              {
                delta: {
                  tool_calls: [
                    {
                      index: 0,
                      id: 'c1',
                      function: { name: 'list_', arguments: '{"a"' },
                    },
                  ],
                },
              },
            ],
          },
          {
            choices: [
              {
                delta: {
                  tool_calls: [
                    {
                      index: 0,
                      function: { name: 'agents', arguments: ':1}' },
                    },
                  ],
                },
              },
            ],
          },
          {
            choices: [],
            usage: { prompt_tokens: 5, completion_tokens: 7, total_tokens: 12 },
          },
          '[DONE]',
        ]),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);
    const seen: string[] = [];

    const res = await new LlmUpstreamClient(cfg).chatStream(
      { messages },
      null,
      (t) => seen.push(t),
      limits,
    );

    expect(seen).toEqual(['Hel', 'lo']);
    const [, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(JSON.parse(init.body as string)).toMatchObject({
      stream: true,
      stream_options: { include_usage: true },
    });
    const choice = (
      res.body.choices as { message: Record<string, unknown> }[]
    )[0]!;
    expect(choice.message).toMatchObject({
      content: 'Hello',
      tool_calls: [
        { id: 'c1', function: { name: 'list_agents', arguments: '{"a":1}' } },
      ],
    });
    expect(res.body.usage).toEqual({
      prompt_tokens: 5,
      completion_tokens: 7,
      total_tokens: 12,
    });
  });

  it('fails with LlmUpstreamError on a non-2xx and never carries the body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(new Response('secret prompt echo', { status: 500 })),
      ),
    );
    await expect(
      new LlmUpstreamClient(cfg).chatStream(
        { messages },
        null,
        () => undefined,
        limits,
      ),
    ).rejects.toThrow('HTTP 500');
  });

  it('gives up when the stream goes silent for longer than the idle limit', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(
              new TextEncoder().encode(
                'data: {"choices":[{"delta":{"content":"a"}}]}\n\n',
              ),
            );
            init.signal?.addEventListener('abort', () =>
              controller.error(new DOMException('x', 'AbortError')),
            );
          },
        });
        return Promise.resolve(new Response(body, { status: 200 }));
      }),
    );
    await expect(
      new LlmUpstreamClient(cfg).chatStream(
        { messages },
        null,
        () => undefined,
        {
          firstTokenMs: 1000,
          idleMs: 50,
          totalMs: 5000,
        },
      ),
    ).rejects.toThrow('LLM upstream failed');
  });

  it('stops when the client goes away', async () => {
    const ctl = new AbortController();
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            init.signal?.addEventListener('abort', () =>
              controller.error(new DOMException('x', 'AbortError')),
            );
          },
        });
        return Promise.resolve(new Response(body, { status: 200 }));
      }),
    );
    const run = new LlmUpstreamClient(cfg).chatStream(
      { messages },
      null,
      () => undefined,
      {
        ...limits,
        signal: ctl.signal,
      },
    );
    setTimeout(() => ctl.abort(), 20);
    await expect(run).rejects.toThrow('LLM upstream failed');
  });
});
