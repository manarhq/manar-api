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

/**
 * A minimal mTLS-authenticated JSON request helper, used by
 * `ManarAgent.authorize`/`delegateTask` (Phase 5). Deliberately built on
 * `node:https` directly rather than the global `fetch` — Node's
 * WHATWG-`fetch` implementation (undici) doesn't accept a plain
 * `node:https`-style client-certificate option the way `https.request`
 * does, and this SDK has no other reason to depend on a third-party HTTP
 * client just for this. Mirrors the pattern `test/agent-identity.e2e-spec.ts`
 * already uses for its own raw mTLS requests against `/agent/v1/whoami`.
 */
export async function mtlsRequestJson<T>(
  options: MtlsRequestOptions,
): Promise<T> {
  const url = new URL(options.path, options.endpoint);
  const bodyText =
    options.body !== undefined ? JSON.stringify(options.body) : undefined;

  return new Promise<T>((resolve, reject) => {
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

          if (status >= 200 && status < 300) {
            resolve(parsed as T);
            return;
          }

          const message =
            parsed && typeof parsed === 'object' && 'message' in parsed
              ? String(parsed.message)
              : `HTTP ${status}`;
          reject(
            new Error(`mTLS request to ${options.path} failed: ${message}`),
          );
        });
      },
    );

    request.on('error', reject);
    if (bodyText) request.write(bodyText);
    request.end();
  });
}
