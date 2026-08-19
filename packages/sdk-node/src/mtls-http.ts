import * as https from 'node:https';
import type { AgentIdentity } from './identity-store';

export interface MtlsRequestOptions {
  /** Base URL of manar-api's agent-facing mTLS HTTPS listener (e.g. https://127.0.0.1:3443) — NOT the human-facing HTTP endpoint `enroll()` uses. */
  endpoint: string;
  path: string;
  method: 'GET' | 'POST';
  body?: unknown;
  identity: AgentIdentity;
}

export interface MtlsRawResponse {
  status: number;
  body: unknown;
}

/**
 * The raw, non-throwing mTLS-authenticated JSON request primitive both
 * `mtlsRequestJson` and `ManarAgent.invokeTool` build on. Deliberately
 * built on `node:https` directly rather than the global `fetch` — Node's
 * WHATWG-`fetch` implementation (undici) doesn't accept a plain
 * `node:https`-style client-certificate option the way `https.request`
 * does, and this SDK has no other reason to depend on a third-party HTTP
 * client just for this. Mirrors the pattern `test/agent-identity.e2e-spec.ts`
 * already uses for its own raw mTLS requests against `/agent/v1/whoami`.
 * Never rejects on a non-2xx status — every status code this SDK cares
 * about (200/202/403/...) is a meaningful, structured JSON response the
 * caller decides how to interpret; only a genuine transport failure
 * rejects.
 */
export async function mtlsRequestRaw(
  options: MtlsRequestOptions,
): Promise<MtlsRawResponse> {
  const url = new URL(options.path, options.endpoint);
  const bodyText =
    options.body !== undefined ? JSON.stringify(options.body) : undefined;

  return new Promise<MtlsRawResponse>((resolve, reject) => {
    const request = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: options.method,
        cert: options.identity.certificatePem,
        key: options.identity.privateKeyPem,
        ca: options.identity.caChainPem,
        rejectUnauthorized: true,
        headers: bodyText
          ? {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(bodyText),
            }
          : undefined,
      },
      (response) => {
        let raw = '';
        response.on('data', (chunk: Buffer) => {
          raw += chunk.toString('utf8');
        });
        response.on('end', () => {
          const status = response.statusCode ?? 0;
          let parsed: unknown;
          try {
            parsed = raw ? JSON.parse(raw) : undefined;
          } catch {
            parsed = undefined;
          }
          resolve({ status, body: parsed });
        });
      },
    );

    request.on('error', reject);
    if (bodyText) request.write(bodyText);
    request.end();
  });
}

/**
 * A minimal mTLS-authenticated JSON request helper, used by
 * `ManarAgent.authorize`/`delegateTask` (Phase 5) — both endpoints only
 * ever have one meaningful shape of response, always on a 2xx status, so
 * this thin wrapper over `mtlsRequestRaw` rejects on anything else.
 */
export async function mtlsRequestJson<T>(
  options: MtlsRequestOptions,
): Promise<T> {
  const { status, body } = await mtlsRequestRaw(options);

  if (status >= 200 && status < 300) {
    return body as T;
  }

  const message =
    body && typeof body === 'object' && 'message' in body
      ? String(body.message)
      : `HTTP ${status}`;
  throw new Error(`mTLS request to ${options.path} failed: ${message}`);
}
