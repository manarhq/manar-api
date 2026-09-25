import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface RecordedLlmCall {
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: Record<string, unknown>;
}

/**
 * A tiny OpenAI-compatible `/v1/chat/completions` upstream for the LLM proxy
 * e2e (ADR-0002), so CI never needs Ollama. Records every request and
 * answers with a fixed completion and `usage`.
 */
export class FakeOpenAiUpstream {
  readonly calls: RecordedLlmCall[] = [];
  completion = 'Fixture completion: isolate fx-ws-042 pending approval.';
  usage = { prompt_tokens: 40, completion_tokens: 20, total_tokens: 60 };
  private server: Server | undefined;

  async start(port = 0): Promise<string> {
    this.server = createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk: Buffer) => (raw += chunk.toString('utf8')));
      req.on('end', () => {
        const body = JSON.parse(raw || '{}') as Record<string, unknown>;
        this.calls.push({ path: req.url ?? '', headers: req.headers, body });
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            id: `chatcmpl-${this.calls.length}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: body.model,
            choices: [
              {
                index: 0,
                message: { role: 'assistant', content: this.completion },
                finish_reason: 'stop',
              },
            ],
            usage: this.usage,
          }),
        );
      });
    });
    await new Promise<void>((resolve) =>
      this.server!.listen(port, '127.0.0.1', resolve),
    );
    return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}/v1`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) =>
      this.server ? this.server.close(() => resolve()) : resolve(),
    );
  }
}
