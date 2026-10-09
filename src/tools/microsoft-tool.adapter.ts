import { createHash } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { AppConfig } from '../config/env.validation';
import {
  OutboundResponseTooLargeError,
  readBoundedResponseText,
  safeOutboundFetch,
  UnsafeOutboundUrlError,
} from '../common/ssrf/url-safety';
import {
  ssrfPolicyFromConfig,
  type SsrfPolicy,
} from '../common/ssrf/ssrf.config';
import { validateAgainstSchema } from './json-schema-validator.util';
import {
  findMicrosoftAction,
  MICROSOFT_SCOPES,
  type MicrosoftCall,
  type MicrosoftRequest,
} from './microsoft-actions';
import type {
  ToolInvocationResult,
  ToolProtocolAdapter,
} from './tool-protocol-adapter.interface';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/**
 * The non-secret half of a Microsoft tool's configuration, stored in
 * `Tool.metadata`. The client secret is the tool's credential and arrives
 * through `CredentialBrokerService` (OpenBao), never from here.
 * `authorityUrl` and `Tool.baseEndpoint` are configurable so tests and the
 * DEMO FIXTURE can stand in for Microsoft.
 */
const MicrosoftToolMetadataSchema = z.object({
  api: z.enum(['graph', 'defender']),
  azureTenantId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$/),
  clientId: z.string().regex(/^[0-9a-fA-F-]{36}$/),
  authorityUrl: z.url().default('https://login.microsoftonline.com'),
  /** Deadline for each token or API request, body included. */
  requestTimeoutMs: z.number().int().min(100).max(120_000).default(15_000),
});

type MicrosoftToolMetadata = z.infer<typeof MicrosoftToolMetadataSchema>;

/** A cached token is dropped this long before Entra says it expires. */
const TOKEN_EXPIRY_SKEW_MS = 60_000;
const READ_MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 200;
/** Errors that prove the request never left this process. */
const NOT_SENT_ERROR_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
]);

const TokenResponseSchema = z.object({
  access_token: z.string().min(1),
  expires_in: z.coerce.number().positive(),
});

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function errorCode(error: unknown): string | undefined {
  const cause = (error as { cause?: { code?: unknown } } | null)?.cause;
  return typeof cause?.code === 'string' ? cause.code : undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Executes the Microsoft action catalog (`microsoft-actions.ts`) for a
 * `Tool` with `protocol: MICROSOFT` (ADR-0004). It is one more
 * `ToolProtocolAdapter` behind `CredentialBrokerService`, so authorization,
 * approvals, kill switches, DLP and audit all run before it exactly as they
 * do for HTTP and MCP tools.
 *
 * Per call: validate the action, `resource` and `params` against the
 * catalog; get an app-only token for the API's scope with the OAuth2
 * client-credentials grant (the broker-resolved client secret is used for
 * that one request and is the only thing it is used for); send the one
 * Graph/Defender request with that token. Every outbound request, token
 * endpoint included, goes through `safeOutboundFetch`.
 *
 * Tokens are cached in this process only, until `TOKEN_EXPIRY_SKEW_MS`
 * before expiry, keyed by a hash that includes the client secret, so a
 * tool cannot reuse a token cached for different credentials. Tokens are
 * never persisted, logged or returned.
 *
 * Outcome rules (Gate 0 R1, same as `HttpToolAdapter`): reads are retried
 * on 429/5xx/network errors; a mutating or destructive action gets one
 * attempt. A failure to get a token is a definite FAILURE: the action was
 * never sent. After the action was sent, a timeout, dropped connection or
 * 5xx is `outcomeUnknown`. Any other 4xx, and a 429 on a mutation, is
 * Microsoft refusing the request, so a definite FAILURE.
 */
@Injectable()
export class MicrosoftToolAdapter implements ToolProtocolAdapter {
  private readonly logger = new Logger(MicrosoftToolAdapter.name);
  private readonly ssrfPolicy: SsrfPolicy;
  private readonly tokens = new Map<string, Promise<CachedToken>>();

  constructor(configService: ConfigService<AppConfig, true>) {
    this.ssrfPolicy = ssrfPolicyFromConfig(configService);
  }

  async invoke(
    tool: ToolRecord,
    action: ToolActionRecord,
    resource: string,
    params: unknown,
    credential: string,
  ): Promise<ToolInvocationResult> {
    const def = findMicrosoftAction(action.name);
    const metadata = MicrosoftToolMetadataSchema.safeParse(tool.metadata);
    if (!metadata.success) {
      return { success: false, errorMessage: 'invalid_microsoft_tool_config' };
    }
    if (!def || def.api !== metadata.data.api) {
      return { success: false, errorMessage: 'unknown_microsoft_action' };
    }
    if (!def.resource.test(resource)) {
      return {
        success: false,
        errorMessage: `Invalid resource for action "${def.name}"`,
      };
    }
    const validation = validateAgainstSchema(def.inputSchema, params ?? {});
    if (!validation.valid) {
      return {
        success: false,
        errorMessage: `Invalid params for action "${def.name}": ${validation.errors}`,
      };
    }
    const values = (params ?? {}) as Record<string, unknown>;

    // The catalog flags are the truth for retry safety; the row is only a
    // copy of them, so either one saying "side effect" means one attempt
    // (for every step but a GET inside a multi-step action).
    const sideEffecting =
      def.mutating || def.destructive || action.mutating || action.destructive;

    let accessToken: string;
    try {
      accessToken = await this.token(metadata.data, credential);
    } catch (error) {
      this.logger.warn(
        `Token acquisition for "${tool.name}/${def.name}" failed: ${error instanceof Error ? error.message : 'unknown'}`,
      );
      return { success: false, errorMessage: 'token_acquisition_failed' };
    }

    const call: MicrosoftCall = (request) =>
      this.send(
        tool,
        def.name,
        request,
        accessToken,
        sideEffecting && request.method !== 'GET',
        metadata.data,
        credential,
      );
    if (def.run) return def.run(resource, values, call);
    if (!def.build) {
      return { success: false, errorMessage: 'unknown_microsoft_action' };
    }
    return call(def.build(resource, values));
  }

  private async send(
    tool: ToolRecord,
    actionName: string,
    request: MicrosoftRequest,
    accessToken: string,
    sideEffecting: boolean,
    metadata: MicrosoftToolMetadata,
    credential: string,
  ): Promise<ToolInvocationResult> {
    const base = new URL(
      tool.baseEndpoint.endsWith('/')
        ? tool.baseEndpoint
        : `${tool.baseEndpoint}/`,
    ).href;
    const url = new URL(request.path, base);
    for (const [key, value] of Object.entries(request.query ?? {})) {
      url.searchParams.set(key, value);
    }
    if (!url.href.startsWith(base)) {
      return { success: false, errorMessage: 'unknown_microsoft_action' };
    }

    const maxAttempts = sideEffecting ? 1 : READ_MAX_ATTEMPTS;
    let lastError = 'request failed';
    let mayHaveReachedTool = false;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const final = await this.timed(metadata, async (signal) => {
          const response = await this.fetch(url.toString(), signal, {
            method: request.method,
            headers: {
              Authorization: `Bearer ${accessToken}`,
              ...(request.body !== undefined
                ? { 'Content-Type': 'application/json' }
                : {}),
            },
            body:
              request.body !== undefined
                ? JSON.stringify(request.body)
                : undefined,
          });
          if (response.ok) {
            const data = await this.readBody(response, sideEffecting);
            return { success: true, data } satisfies ToolInvocationResult;
          }
          const code = await this.errorCodeOf(response);
          lastError = `HTTP ${response.status}${code ? ` ${code}` : ''}`;
          if (response.status === 401) {
            // A rejected token must not be served from the cache again.
            this.tokens.delete(this.cacheKey(metadata, credential));
          }
          if (
            (response.status < 500 && response.status !== 429) ||
            (response.status === 429 && sideEffecting)
          ) {
            // Microsoft refused it (a 429 is throttled before processing):
            // nothing happened, and a retry would not change the answer.
            return { success: false, errorMessage: lastError };
          }
          mayHaveReachedTool = response.status >= 500;
          return undefined;
        });
        if (final) return final;
      } catch (error) {
        if (error instanceof UnsafeOutboundUrlError) {
          this.logger.warn(
            `Blocked Microsoft call "${tool.name}/${actionName}": ${error.reasonCode}`,
          );
          return {
            success: false,
            errorMessage: 'blocked_by_outbound_url_policy',
          };
        }
        if (error instanceof OutboundResponseTooLargeError) {
          return { success: false, errorMessage: 'response_too_large' };
        }
        lastError =
          error instanceof Error && error.name === 'AbortError'
            ? 'request timed out'
            : 'request failed';
        mayHaveReachedTool = !NOT_SENT_ERROR_CODES.has(errorCode(error) ?? '');
      }
      if (attempt < maxAttempts) await sleep(RETRY_DELAY_MS);
    }

    if (sideEffecting && mayHaveReachedTool) {
      this.logger.error(
        `Microsoft call "${tool.name}/${actionName}" ended without a definite answer (${lastError}); outcome UNKNOWN, not retried`,
      );
      return { success: false, errorMessage: lastError, outcomeUnknown: true };
    }
    return { success: false, errorMessage: lastError };
  }

  private token(
    metadata: MicrosoftToolMetadata,
    clientSecret: string,
  ): Promise<string> {
    const key = this.cacheKey(metadata, clientSecret);
    const cached = this.tokens.get(key);
    if (cached) {
      return cached.then((t) =>
        t.expiresAt > Date.now()
          ? t.accessToken
          : this.refreshToken(key, metadata, clientSecret),
      );
    }
    return this.refreshToken(key, metadata, clientSecret);
  }

  private async refreshToken(
    key: string,
    metadata: MicrosoftToolMetadata,
    clientSecret: string,
  ): Promise<string> {
    const pending = this.requestToken(metadata, clientSecret);
    this.tokens.set(key, pending);
    try {
      return (await pending).accessToken;
    } catch (error) {
      if (this.tokens.get(key) === pending) this.tokens.delete(key);
      throw error;
    }
  }

  private async requestToken(
    metadata: MicrosoftToolMetadata,
    clientSecret: string,
  ): Promise<CachedToken> {
    const url = `${metadata.authorityUrl.replace(/\/+$/, '')}/${encodeURIComponent(metadata.azureTenantId)}/oauth2/v2.0/token`;
    const text = await this.timed(metadata, async (signal) => {
      let response: Response;
      try {
        response = await this.fetch(url, signal, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: metadata.clientId,
            client_secret: clientSecret,
            scope: MICROSOFT_SCOPES[metadata.api],
          }).toString(),
        });
      } catch (error) {
        throw new Error(
          error instanceof UnsafeOutboundUrlError
            ? `blocked: ${error.reasonCode}`
            : 'token endpoint unreachable',
        );
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`token endpoint HTTP ${response.status}`);
      }
      return readBoundedResponseText(response);
    });
    const body = TokenResponseSchema.safeParse(safeJson(text));
    if (!body.success) {
      throw new Error('token endpoint returned no token');
    }
    return {
      accessToken: body.data.access_token,
      expiresAt:
        Date.now() + body.data.expires_in * 1000 - TOKEN_EXPIRY_SKEW_MS,
    };
  }

  private cacheKey(metadata: MicrosoftToolMetadata, clientSecret: string) {
    return createHash('sha256')
      .update(
        [
          metadata.authorityUrl,
          metadata.azureTenantId,
          metadata.clientId,
          MICROSOFT_SCOPES[metadata.api],
          clientSecret,
        ].join('\n'),
      )
      .digest('hex');
  }

  /** Runs one request, body read included, under the request deadline. */
  private async timed<T>(
    metadata: MicrosoftToolMetadata,
    fn: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      metadata.requestTimeoutMs,
    );
    try {
      return await fn(controller.signal);
    } finally {
      clearTimeout(timeout);
    }
  }

  private fetch(
    url: string,
    signal: AbortSignal,
    init: { method: string; headers: Record<string, string>; body?: string },
  ): Promise<Response> {
    if (!url.startsWith('https:') && !this.ssrfPolicy.allowLoopback) {
      // A bearer token or client secret never travels in clear text outside development.
      throw new UnsafeOutboundUrlError(url, 'https_required');
    }
    return safeOutboundFetch(url, { ...init, signal, ...this.ssrfPolicy });
  }

  /** A 2xx body; for a side effect that already happened, an unreadable body does not turn it into a failure. */
  private async readBody(
    response: Response,
    sideEffecting: boolean,
  ): Promise<unknown> {
    try {
      const text = await readBoundedResponseText(response);
      return text ? (JSON.parse(text) as unknown) : { status: response.status };
    } catch (error) {
      if (sideEffecting) return { status: response.status };
      throw error;
    }
  }

  /** Microsoft's `error.code` (a short identifier), never the message, which can echo request data. */
  private async errorCodeOf(response: Response): Promise<string | undefined> {
    try {
      const body = JSON.parse(await readBoundedResponseText(response)) as {
        error?: { code?: unknown };
      };
      const code = body.error?.code;
      return typeof code === 'string' && /^[A-Za-z0-9_.]{1,64}$/.test(code)
        ? code
        : undefined;
    } catch {
      return undefined;
    }
  }
}
