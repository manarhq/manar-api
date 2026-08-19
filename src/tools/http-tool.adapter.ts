import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import {
  assertSafeOutboundUrl,
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
 * framework needed"): up to `MAX_ATTEMPTS` total attempts, a short fixed
 * delay between them, retrying only on what looks like a *transient*
 * failure — a network-level error (`fetch` itself rejecting: DNS,
 * connection refused, timeout) or an HTTP 5xx response. A 4xx response is
 * never retried (it's the tool's own considered answer that this specific
 * request is invalid — retrying it verbatim would never succeed). This is
 * deliberately not safe for non-idempotent actions in general (a POST that
 * partially succeeded server-side before the response was lost would be
 * retried) — acceptable for this phase's scope per the design spec; a real
 * integration wanting idempotency would need the target tool to support an
 * idempotency key, which is out of scope here.
 */
const MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 200;

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

    // Phase 12a (SSRF protection): re-validated on *every* call, never just
    // once when the Tool was registered -- a hostname that resolved safely
    // then could have been repointed at an internal address since (DNS
    // rebinding). See src/common/ssrf/url-safety.ts's doc comment.
    try {
      await assertSafeOutboundUrl(url.toString(), {
        allowedHosts: this.ssrfAllowedHosts,
      });
    } catch (error) {
      if (error instanceof UnsafeOutboundUrlError) {
        this.logger.warn(
          `Blocked HTTP tool call to "${tool.name}/${action.name}": ${error.reasonCode}`,
        );
        return {
          success: false,
          errorMessage: 'blocked_by_outbound_url_policy',
        };
      }
      throw error;
    }

    let lastError: string = 'request failed';
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${credential}`,
          },
          body: JSON.stringify({ resource, params }),
          signal: controller.signal,
        });

        if (response.ok) {
          const data: unknown = await response.json().catch(() => undefined);
          return { success: true, data };
        }

        lastError = `HTTP ${response.status}`;
        if (response.status < 500) {
          // A 4xx is the tool's own considered answer -- never retried.
          return { success: false, errorMessage: lastError };
        }
      } catch (error) {
        lastError =
          error instanceof Error && error.name === 'AbortError'
            ? 'request timed out'
            : `request failed: ${error instanceof Error ? error.message : String(error)}`;
      } finally {
        clearTimeout(timeout);
      }

      if (attempt < MAX_ATTEMPTS) {
        this.logger.warn(
          `HTTP tool call to "${tool.name}/${action.name}" attempt ${attempt} failed (${lastError}) — retrying`,
        );
        await sleep(RETRY_DELAY_MS);
      }
    }

    return { success: false, errorMessage: lastError };
  }
}
