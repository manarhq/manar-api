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
  findGitLabAction,
  GITLAB_PROJECT,
  parseGitLabResource,
  type GitLabRequest,
} from './gitlab-actions';
import type {
  ToolInvocationResult,
  ToolProtocolAdapter,
} from './tool-protocol-adapter.interface';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/**
 * The non-secret half of a GitLab tool's configuration (`Tool.metadata`).
 * `project` is the one project this tool may act on; `Tool.baseEndpoint` is
 * the instance's `/api/v4` URL. The token is the tool's credential and
 * arrives through `CredentialBrokerService` (OpenBao), never from here.
 */
const GitLabToolMetadataSchema = z.object({
  project: z.string().regex(GITLAB_PROJECT),
  // GitLab merges can take tens of seconds on a busy instance (a 15 s deadline
  // turned a live merge into UNKNOWN on 9 Oct 2026).
  requestTimeoutMs: z.number().int().min(100).max(120_000).default(60_000),
});
type GitLabToolMetadata = z.infer<typeof GitLabToolMetadataSchema>;

const READ_MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 200;
/** How long a precheck waits for GitLab to finish computing a state (10 x 1 s). */
const SETTLE_MAX_READS = 10;
const SETTLE_DELAY_MS = 1_000;
/** Errors that prove the request never left this process. */
const NOT_SENT_ERROR_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
]);
/**
 * GitLab answers 400 with a Gitaly deadline message when its storage layer
 * timed out; the write may still have landed (seen live on gitlab.vax.sh,
 * 9 Oct 2026), so for a mutation that is not a definite failure.
 */
const GITALY_TIMEOUT = /deadline exceeded|stream removed/i;
/** Fixed words for the error statuses an agent can act on; GitLab's own message is never passed on. */
const STATUS_WORDS: Record<number, string> = {
  400: 'rejected',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  405: 'not_allowed',
  406: 'not_mergeable',
  409: 'conflict',
  422: 'unprocessable',
};

function errorCode(error: unknown): string | undefined {
  const cause = (error as { cause?: { code?: unknown } } | null)?.cause;
  return typeof cause?.code === 'string' ? cause.code : undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

type Attempt =
  | { kind: 'ok'; body: unknown }
  | { kind: 'status'; status: number; gitalyTimeout: boolean }
  | { kind: 'error'; message: string; maybeSent: boolean }
  | { kind: 'final'; result: ToolInvocationResult };

/**
 * Executes the GitLab catalog (`gitlab-actions.ts`) for a `Tool` with
 * `protocol: GITLAB` (ADR-0012), behind `CredentialBrokerService` like every
 * other adapter, so authorization, approvals, kill switches, DLP and audit
 * all run before it.
 *
 * Per call: validate the action, `resource` and `params` against the
 * catalog; refuse a resource whose project is not the tool's configured
 * project; build the one URL under `<baseEndpoint>/projects/<project>/`;
 * send it with the broker-resolved token in `PRIVATE-TOKEN`, through
 * `safeOutboundFetch`, over HTTPS outside development.
 *
 * Outcome rules (Gate 0 R1, as in the other adapters): reads are retried on
 * 429/5xx/network errors; a mutation gets one attempt. After a mutation was
 * sent, a timeout, dropped connection, 5xx or Gitaly deadline is
 * `outcomeUnknown`; any other 4xx is GitLab refusing it, a definite FAILURE.
 * A failed precheck (commit to a protected branch) is a FAILURE with nothing
 * sent but the read.
 */
@Injectable()
export class GitLabToolAdapter implements ToolProtocolAdapter {
  private readonly logger = new Logger(GitLabToolAdapter.name);
  private readonly ssrfPolicy: SsrfPolicy;

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
    const def = findGitLabAction(action.name);
    const metadata = GitLabToolMetadataSchema.safeParse(tool.metadata);
    if (!metadata.success) {
      return { success: false, errorMessage: 'invalid_gitlab_tool_config' };
    }
    // The token is bound to one host by two independent settings: the tool
    // row and the operator's SSRF_ALLOWED_HOSTS. Both must name it.
    let host: string;
    try {
      host = new URL(tool.baseEndpoint).hostname;
    } catch {
      return { success: false, errorMessage: 'invalid_gitlab_tool_config' };
    }
    if (!this.ssrfPolicy.allowedHosts.has(host)) {
      this.logger.warn(
        `Refused "${tool.name}/${action.name}": base endpoint host is not in SSRF_ALLOWED_HOSTS`,
      );
      return { success: false, errorMessage: 'gitlab_host_not_allowed' };
    }
    if (!def) return { success: false, errorMessage: 'unknown_gitlab_action' };
    const target = parseGitLabResource(def.resource, resource);
    if (!target) {
      return {
        success: false,
        errorMessage: `Invalid resource for action "${def.name}"`,
      };
    }
    if (target.project !== metadata.data.project) {
      this.logger.warn(
        `Refused "${tool.name}/${def.name}": resource outside the tool's project`,
      );
      return { success: false, errorMessage: 'resource_outside_tool_project' };
    }
    const validation = validateAgainstSchema(def.inputSchema, params ?? {});
    if (!validation.valid) {
      return {
        success: false,
        errorMessage: `Invalid params for action "${def.name}": ${validation.errors}`,
      };
    }
    const p = (params ?? {}) as Record<string, unknown>;
    const sideEffecting =
      def.mutating || def.destructive || action.mutating || action.destructive;
    const ctx = { tool, metadata: metadata.data, credential, name: def.name };

    if (def.precheck) {
      let checked = await this.send(ctx, def.precheck.request(target), false);
      for (
        let wait = 0;
        wait < SETTLE_MAX_READS &&
        checked.kind === 'ok' &&
        def.precheck.settling?.(checked.body);
        wait += 1
      ) {
        await sleep(SETTLE_DELAY_MS);
        checked = await this.send(ctx, def.precheck.request(target), false);
      }
      if (checked.kind === 'final') return checked.result;
      const missing = checked.kind === 'status' && checked.status === 404;
      if (checked.kind !== 'ok' && !missing) {
        // Fail closed: no change without a definite answer about the state.
        return { success: false, errorMessage: this.describe(checked) };
      }
      const refusal = def.precheck.refuse(
        checked.kind === 'ok' ? checked.body : undefined,
        target,
        p,
      );
      if (refusal) return { success: false, errorMessage: refusal };
    }

    let answer = await this.send(ctx, def.build(target, p), sideEffecting);
    if (answer.kind === 'status' && answer.status === 404 && def.onNotFound) {
      // A 404 changed nothing, so the create half is still a first attempt.
      answer = await this.send(ctx, def.onNotFound(target, p), sideEffecting);
    }

    switch (answer.kind) {
      case 'final':
        return answer.result;
      case 'ok': {
        const violation = def.postcheck?.(answer.body, p);
        if (violation) {
          this.logger.error(
            `GitLab call "${tool.name}/${def.name}" ran but broke its approval binding (${violation})`,
          );
          return {
            success: false,
            errorMessage: violation,
            outcomeUnknown: true,
            bindingViolation: violation,
          };
        }
        return {
          success: true,
          data: def.shape ? def.shape(answer.body) : answer.body,
        };
      }
      default: {
        const errorMessage = this.describe(answer);
        const unknown =
          sideEffecting &&
          (answer.kind === 'error'
            ? answer.maybeSent
            : answer.status >= 500 || answer.gitalyTimeout);
        if (unknown) {
          this.logger.error(
            `GitLab call "${tool.name}/${def.name}" ended without a definite answer (${errorMessage}); outcome UNKNOWN, not retried`,
          );
          return { success: false, errorMessage, outcomeUnknown: true };
        }
        return { success: false, errorMessage };
      }
    }
  }

  private describe(a: Exclude<Attempt, { kind: 'ok' | 'final' }>): string {
    if (a.kind === 'error') return a.message;
    const word = a.gitalyTimeout ? 'storage_timeout' : STATUS_WORDS[a.status];
    return `HTTP ${a.status}${word ? ` ${word}` : ''}`;
  }

  private async send(
    ctx: {
      tool: ToolRecord;
      metadata: GitLabToolMetadata;
      credential: string;
      name: string;
    },
    request: GitLabRequest,
    sideEffecting: boolean,
  ): Promise<Attempt> {
    const base = new URL(
      ctx.tool.baseEndpoint.endsWith('/')
        ? ctx.tool.baseEndpoint
        : `${ctx.tool.baseEndpoint}/`,
    ).href;
    const projectBase = new URL(
      `projects/${encodeURIComponent(ctx.metadata.project)}/`,
      base,
    );
    const url = new URL(request.path, projectBase);
    for (const [key, value] of Object.entries(request.query ?? {})) {
      url.searchParams.set(key, value);
    }
    // Every catalog path is relative and built from encoded segments; this
    // refuses anything that still resolves off the project (another origin,
    // a protocol-relative or absolute path, a dot segment).
    if (
      url.origin !== projectBase.origin ||
      !url.pathname.startsWith(projectBase.pathname) ||
      url.username !== '' ||
      url.password !== ''
    ) {
      return {
        kind: 'final',
        result: { success: false, errorMessage: 'unknown_gitlab_action' },
      };
    }

    const maxAttempts = sideEffecting ? 1 : READ_MAX_ATTEMPTS;
    let last: Attempt = {
      kind: 'error',
      message: 'request failed',
      maybeSent: false,
    };
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      last = await this.attempt(ctx, url.toString(), request, sideEffecting);
      const retryable =
        (last.kind === 'status' &&
          (last.status >= 500 || last.status === 429)) ||
        last.kind === 'error';
      if (!retryable) return last;
      if (attempt < maxAttempts) await sleep(RETRY_DELAY_MS);
    }
    return last;
  }

  private async attempt(
    ctx: {
      tool: ToolRecord;
      metadata: GitLabToolMetadata;
      credential: string;
      name: string;
    },
    url: string,
    request: GitLabRequest,
    sideEffecting: boolean,
  ): Promise<Attempt> {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      ctx.metadata.requestTimeoutMs,
    );
    try {
      if (!url.startsWith('https:') && !this.ssrfPolicy.allowLoopback) {
        // The token never travels in clear text outside development.
        throw new UnsafeOutboundUrlError(url, 'https_required');
      }
      const response = await safeOutboundFetch(url, {
        method: request.method,
        headers: {
          'PRIVATE-TOKEN': ctx.credential,
          ...(request.body !== undefined
            ? { 'Content-Type': 'application/json' }
            : {}),
        },
        body:
          request.body !== undefined ? JSON.stringify(request.body) : undefined,
        signal: controller.signal,
        ...this.ssrfPolicy,
        // GitLab's API does not redirect; a 3xx is refused, not followed,
        // so the token is only ever sent to the URL built above.
        maxRedirects: 0,
      });
      const text = await readBoundedResponseText(response).catch(
        (error: unknown) => {
          if (error instanceof OutboundResponseTooLargeError) throw error;
          return '';
        },
      );
      if (response.ok) {
        try {
          return {
            kind: 'ok',
            body: text
              ? (JSON.parse(text) as unknown)
              : { status: response.status },
          };
        } catch {
          // A side effect that already happened stays a success.
          return sideEffecting
            ? { kind: 'ok', body: { status: response.status } }
            : { kind: 'error', message: 'invalid response', maybeSent: true };
        }
      }
      return {
        kind: 'status',
        status: response.status,
        gitalyTimeout: response.status === 400 && GITALY_TIMEOUT.test(text),
      };
    } catch (error) {
      if (error instanceof UnsafeOutboundUrlError) {
        this.logger.warn(
          `Blocked GitLab call "${ctx.tool.name}/${ctx.name}": ${error.reasonCode}`,
        );
        return {
          kind: 'final',
          result: {
            success: false,
            errorMessage: 'blocked_by_outbound_url_policy',
          },
        };
      }
      if (error instanceof OutboundResponseTooLargeError) {
        return {
          kind: 'final',
          result: { success: false, errorMessage: 'response_too_large' },
        };
      }
      return {
        kind: 'error',
        message:
          error instanceof Error && error.name === 'AbortError'
            ? 'request timed out'
            : 'request failed',
        maybeSent: !NOT_SENT_ERROR_CODES.has(errorCode(error) ?? ''),
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}
