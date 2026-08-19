import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

/** One request the fixture server actually received — recorded verbatim so tests can assert on it (e.g. the `Authorization` header actually sent, proving credential injection worked). */
export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: unknown;
  /** Phase 12a: the exact raw request body bytes (as a UTF-8 string), captured alongside the parsed `body` above — webhook signature verification (`verifyWebhookSignature`) must hash the exact bytes the sender signed, not a re-`JSON.stringify`d reconstruction of the parsed value, which could in principle differ (e.g. numeric formatting). */
  rawBody: string;
}

export interface HttpFixtureResponse {
  status: number;
  body: unknown;
}

/**
 * A lightweight local HTTP server this phase's own tests stand up to play
 * the role of "a real registered `Tool`'s `baseEndpoint`" — not one of
 * Phase 7a's actual demo SOC tool backends (this workstream doesn't depend
 * on that existing yet — see the design spec's "Runs in parallel with
 * Phase 7a" note). Records every request it receives (for asserting *zero*
 * requests were made on a `DENY`/`REQUIRE_APPROVAL`, and for inspecting
 * exactly what `HttpToolAdapter` sent), and answers with a configurable
 * response (defaults to a 200 JSON echo of what it received, standing in
 * for "the tool's real response").
 */
export class HttpFixtureServer {
  private server: http.Server | undefined;
  private response:
    HttpFixtureResponse | ((req: RecordedRequest) => HttpFixtureResponse) = (
    req,
  ) => ({ status: 200, body: { echoed: req.body } });

  readonly requests: RecordedRequest[] = [];

  async start(): Promise<string> {
    this.server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        const rawBody = Buffer.concat(chunks).toString('utf8');
        let parsedBody: unknown = undefined;
        if (rawBody) {
          try {
            parsedBody = JSON.parse(rawBody);
          } catch {
            parsedBody = rawBody;
          }
        }

        const recorded: RecordedRequest = {
          method: req.method ?? 'GET',
          path: req.url ?? '/',
          headers: req.headers,
          body: parsedBody,
          rawBody,
        };
        this.requests.push(recorded);

        const resolved =
          typeof this.response === 'function'
            ? this.response(recorded)
            : this.response;
        res.writeHead(resolved.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(resolved.body));
      });
    });

    await new Promise<void>((resolve) =>
      this.server?.listen(0, '127.0.0.1', resolve),
    );
    const address = this.server.address() as AddressInfo;
    return `http://127.0.0.1:${address.port}`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server?.close((error) => (error ? reject(error) : resolve()));
    });
  }

  /** Overrides the default echo response — e.g. a fixed failure status to prove `HttpToolAdapter` surfaces it, or a repeated 503 to prove the retry policy. */
  setResponse(
    response:
      HttpFixtureResponse | ((req: RecordedRequest) => HttpFixtureResponse),
  ): void {
    this.response = response;
  }

  reset(): void {
    this.requests.length = 0;
  }
}
