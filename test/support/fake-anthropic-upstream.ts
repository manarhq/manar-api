import { createServer, type Server } from 'node:http';
import type { RecordedLlmCall } from './fake-openai-upstream';

/**
 * A tiny Anthropic `/v1/messages` upstream for the Anthropic-format proxy e2e, so CI never
 * calls Anthropic or Microsoft Foundry. Records every request; answers a message, or the same
 * message as SSE events when the request asks to stream.
 */
export class FakeAnthropicUpstream {
  readonly calls: RecordedLlmCall[] = [];
  text = 'Fixture reply: the repository has 3 files.';
  usage = { input_tokens: 20, output_tokens: 10, cache_read_input_tokens: 5 };
  private server: Server | undefined;

  async start(port: number): Promise<void> {
    this.server = createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk: Buffer) => (raw += chunk.toString('utf8')));
      req.on('end', () => {
        const body = JSON.parse(raw || '{}') as Record<string, unknown>;
        this.calls.push({ path: req.url ?? '', headers: req.headers, body });
        const message = {
          id: `msg_${this.calls.length}`,
          type: 'message',
          role: 'assistant',
          model: body.model,
          content: [{ type: 'text', text: this.text }],
          stop_reason: 'end_turn',
          stop_sequence: null,
          usage: this.usage,
        };
        if (!body.stream) {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(message));
          return;
        }
        const event = (type: string, data: Record<string, unknown>) =>
          `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.write(
          event('message_start', {
            message: { ...message, content: [], stop_reason: null },
          }),
        );
        res.write(
          event('content_block_start', {
            index: 0,
            content_block: { type: 'text', text: '' },
          }),
        );
        res.write(
          event('content_block_delta', {
            index: 0,
            delta: { type: 'text_delta', text: this.text },
          }),
        );
        res.write(event('content_block_stop', { index: 0 }));
        res.write(
          event('message_delta', {
            delta: { stop_reason: 'end_turn', stop_sequence: null },
            usage: { output_tokens: this.usage.output_tokens },
          }),
        );
        res.end(event('message_stop', {}));
      });
    });
    await new Promise<void>((resolve) =>
      this.server!.listen(port, '127.0.0.1', resolve),
    );
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) =>
      this.server ? this.server.close(() => resolve()) : resolve(),
    );
  }
}
