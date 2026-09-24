import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import {
  OutboundResponseTooLargeError,
  readBoundedResponseText,
  safeOutboundFetch,
  UnsafeOutboundUrlError,
} from '../common/ssrf/url-safety';
import { parseSsrfAllowedHosts } from '../common/ssrf/ssrf.config';
import { validateAgainstSchema } from './json-schema-validator.util';
import type {
  ToolInvocationResult,
  ToolProtocolAdapter,
} from './tool-protocol-adapter.interface';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/** Request timeout — generous enough for a real target tool's own processing time, short enough that a hung agent request doesn't hang forever. Simple, fixed, documented; not per-tool configurable this phase (YAGNI until a real integration needs it). */
const REQUEST_TIMEOUT_MS = 10_000;

/**
 * Retry policy (Section 35: "keep it simple — no exponential-backoff
 * framework needed"): a read-only action gets up to `READ_MAX_ATTEMPTS`
 * attempts with a short fixed delay, retrying only on what looks transient
 * (a network-level error or an HTTP 5xx). A 4xx is never retried.
 *
 * A mutating or destructive action gets exactly one attempt (Gate 0 finding
 * R1: a disable-user or isolate-host call whose response was lost must not
 * be sent again). If that attempt ends without a definite answer (timeout,
 * connection lost after sending, 5xx) the result carries `outcomeUnknown`.
 * A connection that was never established (refused, DNS failure) is a
 * definite FAILURE: nothing was sent.
 */
const READ_MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 200;

/** Errors that prove the request never left this process's network stack. */
const NOT_SENT_ERROR_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
]);

function errorCode(error: unknown): string | undefined {
  const cause = (error as { cause?: { code?: unknown } } | null)?.cause;
  return typeof cause?.code === 'string' ? cause.code : undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Real outbound HTTP calls to `Tool.baseEndpoint` (Phase 7b). Request
 * shape (documented here since there is no external tool-vendor API this
 * phase integrates against — that's a later integration pass): a single
 * `POST` to `new URL(action.name, tool.baseEndpoint)` — i.e. `baseEndpoint`
 * is a base URL and `action.name` is appended as a relative path segment
 * — with a JSON body `{ resource, params }` and the resolved credential
 * injected as `Authorization: Bearer <credential>`. `params` is validated
 * against `action.inputSchema` (JSON Schema, via `ajv`) *before* any
 * network call is made — an invalid payload never reaches the network at
 * all, and never allocates a wasted retry budget.
 */
@Injectable()
export class HttpToolAdapter implements ToolProtocolAdapter {
  private readonly logger = new Logger(HttpToolAdapter.name);
  private readonly ssrfAllowedHosts: Set<string>;

  constructor(configService: ConfigService<AppConfig, true>) {
    this.ssrfAllowedHosts = parseSsrfAllowedHosts(
      configService.get('SSRF_ALLOWED_HOSTS', { infer: true }),
    );
  }

  async invoke(
    tool: ToolRecord,
    action: ToolActionRecord,
    resource: string,
    params: unknown,
    credential: string,
  ): Promise<ToolInvocationResult> {
    const validation = validateAgainstSchema(action.inputSchema, params);
    if (!validation.valid) {
      return {
        success: false,
        errorMessage: `Invalid params for action "${action.name}": ${validation.errors}`,
      };
    }

    const url = new URL(
      action.name,
      tool.baseEndpoint.endsWith('/')
        ? tool.baseEndpoint
        : `${tool.baseEndpoint}/`,
    );

    const sideEffecting = action.mutating || action.destructive;
    const maxAttempts = sideEffecting ? 1 : READ_MAX_ATTEMPTS;
    let lastError: string = 'request failed';
    let mayHaveReachedTool = false;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      try {
        // Phase 12a (SSRF protection), extended: `safeOutboundFetch`
        // re-runs `assertSafeOutboundUrl` on *every* call and on every
        // redirect hop, never just once when the Tool was registered -- a
        // hostname that resolved safely then could have been repointed at
        // an internal address since (DNS rebinding), and a host that
        // resolves safely can still answer `302 Location: <internal>`. It
        // also drops the `Authorization` header below on any cross-origin
        // hop, so a redirecting tool endpoint cannot walk off with the
        // broker-issued credential. See that function's doc comment.
        const response = await safeOutboundFetch(url.toString(), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${credential}`,
          },
          body: JSON.stringify({ resource, params }),
          signal: controller.signal,
          allowedHosts: this.ssrfAllowedHosts,
        });

        if (response.ok) {
          const data = await this.readJsonBody(response);
          return { success: true, data };
        }

        lastError = `HTTP ${response.status}`;
        mayHaveReachedTool = true;
        if (response.status < 500) {
          // A 4xx is the tool's own considered answer -- never retried.
          return { success: false, errorMessage: lastError };
        }
      } catch (error) {
        if (error instanceof UnsafeOutboundUrlError) {
          // A URL-policy rejection is never transient -- the same request
          // would be blocked identically on every remaining attempt, so it
          // returns immediately rather than burning the retry budget.
          this.logger.warn(
            `Blocked HTTP tool call to "${tool.name}/${action.name}": ${error.reasonCode}`,
          );
          return {
            success: false,
            errorMessage: 'blocked_by_outbound_url_policy',
          };
        }
        if (error instanceof OutboundResponseTooLargeError) {
          // Also not transient: the tool answered, just with more than this
          // process is willing to buffer.
          this.logger.warn(
            `HTTP tool call to "${tool.name}/${action.name}" returned an oversized response`,
          );
          return { success: false, errorMessage: 'response_too_large' };
        }
        lastError =
          error instanceof Error && error.name === 'AbortError'
            ? 'request timed out'
            : `request failed: ${error instanceof Error ? error.message : String(error)}`;
        mayHaveReachedTool = !NOT_SENT_ERROR_CODES.has(errorCode(error) ?? '');
      } finally {
        clearTimeout(timeout);
      }

      if (attempt < maxAttempts) {
        this.logger.warn(
          `HTTP tool call to "${tool.name}/${action.name}" attempt ${attempt} failed (${lastError}) — retrying`,
        );
        await sleep(RETRY_DELAY_MS);
      }
    }

    if (sideEffecting && mayHaveReachedTool) {
      this.logger.error(
        `HTTP tool call to "${tool.name}/${action.name}" ended without a definite answer (${lastError}); outcome UNKNOWN, not retried`,
      );
      return { success: false, errorMessage: lastError, outcomeUnknown: true };
    }
    return { success: false, errorMessage: lastError };
  }

  /**
   * Reads a successful tool response as JSON under a hard byte ceiling
   * (`readBoundedResponseText`) rather than with a bare `response.json()`,
   * which would buffer whatever a hostile endpoint chose to send. A body
   * that is not valid JSON is still tolerated as `undefined`, exactly as
   * before — an oversized one is not, and propagates as
   * `OutboundResponseTooLargeError` for `invoke`'s catch to map.
   */
  private async readJsonBody(response: Response): Promise<unknown> {
    const text = await readBoundedResponseText(response);
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return undefined;
    }
  }
}
