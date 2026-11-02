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
