import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { SECRET_PROVIDER } from '../database/secret-provider';
import type { SecretProvider } from '../database/secret-provider';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { AiAdvisoryClient } from '../ai-advisory/ai-advisory-client.service';
import type { DataClassification } from '../common/data-classification';
import { redactedToolResultPlaceholder } from './dlp-redaction.util';
import { classifyDlp } from '../common/dlp/dlp-classification';
import {
  DlpBlockedError,
  ToolActionNotFoundError,
  ToolDisabledError,
  ToolNotFoundError,
} from './credential-broker.errors';
import { HttpToolAdapter } from './http-tool.adapter';
import { McpToolAdapter } from './mcp-tool.adapter';
import { MicrosoftToolAdapter } from './microsoft-tool.adapter';
import { ManarConnectorService } from './manar-connector.service';
import { isManarBuiltin } from './manar-actions';
import type { ToolInvocationResult } from './tool-protocol-adapter.interface';
import { failClosed } from '../common/fail-closed/fail-closed';
import { ToolRegistryService } from './tool-registry.service';
import { HandoverStore } from './handover.store';

/**
 * Phase 10b DLP-before-call checkpoint threshold (see docs/ai-security-model.md).
 * `SEVERITY_HIGH`/`SEVERITY_CRITICAL` block; `SEVERITY_MEDIUM` and below do
 * not. Chosen deliberately above `SEVERITY_MEDIUM` because manar-ai's own
 * documented fail-secure behavior (see manar-ai's docs/ai-security-model.md,
 * "Fail loudly, never fail open or fail silent") escalates *any* DLP result
 * to at least `SEVERITY_MEDIUM` whenever its own internal AI classifier is
 * unavailable — a `source: "system"` marker finding, not a real detection.
 * Blocking on `MEDIUM` would mean manar-ai's own AI-backend outage (a
 * separate concern from `AiAdvisoryClient`'s own reachability to manar-ai
 * itself, which fails to `null` and never blocks at all — see that class's
 * doc comment) could block clean, non-sensitive tool calls purely because
 * its LLM backend was unreachable — the same "AI unavailability must not
 * add restriction beyond the deterministic floor" principle this phase
 * applies everywhere else. `HIGH`/`CRITICAL` are only ever reached by a
 * genuine deterministic pattern match (manar-ai's regex layer, always-on,
 * confidence-independent of its own AI backend) or a real, confident AI
 * finding — never by the AI-unavailable marker alone.
 */
const DLP_BLOCKING_SEVERITIES = new Set(['SEVERITY_HIGH', 'SEVERITY_CRITICAL']);

/** How long a detected prompt-injection attempt keeps the requesting agent's `AgentRiskFlag` active — see that model's doc comment and `RiskEngine`'s `AGENT_RISK_FLAG_BUMP`. Short and fixed: long enough to matter for an agent's next few requests, short enough that a stale flag doesn't linger indefinitely. */
const PROMPT_INJECTION_RISK_FLAG_TTL_MS = 15 * 60 * 1000;

/** What the agent receives instead of a tool result withheld as suspected prompt injection (Gate 0 R5). Fixed: nothing from the result, not even the indicators, reaches the agent. */
const PROMPT_INJECTION_WITHHELD = Object.freeze({
  withheld: true,
  reason: 'prompt_injection_suspected',
});

/**
 * Task 5 (see docs/superpowers/sdd/plan-mvp-unblock, task-5-brief.md):
 * bounded-traversal caps for `collectStructuredInjectionText` below. Both
 * are pure in-process CPU bounds on a synchronous object/array walk. The
 * traversal itself adds no RPC of its own and the per-call
 * `AI_ADVISORY_TIMEOUT_MS` hot-lane deadline is unchanged -- the walk runs
 * entirely *before* the single, unchanged `analyzePromptInjection` call in
 * `applyPostCallAdvisories` (never once per leaf, which would multiply RPC
 * round-trips against that same tight budget), so it must stay fast
 * regardless of that budget. What *does* change: a structured result that
 * has any string-shaped leaf now reaches that `analyzePromptInjection` call
 * at all, where before Task 5 it was skipped outright -- so a
 * structured-result invocation now makes 3 sequential hot-lane RPC calls
 * (`analyzeDlp` before-call, `analyzeDlp` after-call, `analyzePromptInjection`)
 * instead of 2, matching what a string-result invocation already made.
 * Depth 5 is deep enough for a
 * `{ events: [ { description, metadata: {...} } ] }` SIEM-response shape
 * (root object -> array -> event object -> string/metadata object ->
 * metadata's own string values) while still bounding pathological nesting.
 */
const PROMPT_INJECTION_SCAN_MAX_DEPTH = 5;
/**
 * ~4KB cap on collected leaf-string content walked out of the structured
 * result, not an exact byte-size cap on the final joined RPC payload --
 * `collectStructuredInjectionText` joins collected leaves with `'\n'`,
 * which can add up to (leaf count - 1) extra characters beyond this cap
 * (e.g. ~4000 single-char leaves could join to ~8000 chars). Harmless
 * either way since the result is still bounded, just not exactly 4KB.
 * Large enough to catch a realistic multi-event tool payload, small enough
 * that a huge or adversarial tool response can't blow past it. The cap
 * truncates rather than drops the call: a truncated-but-still-inspected
 * payload is strictly better than skipping detection outright once the
 * bound is hit. Note also that `remaining` only decrements on non-empty
 * string leaves, so this traversal has no independent node-count bound --
 * a large array of numbers/empty strings within the depth cap is walked in
 * full. That's fine in practice: the same request already does an
 * unbounded `JSON.stringify(originalData)` for the DLP call earlier in
 * `applyPostCallAdvisories`, so this traversal is strictly cheaper than
 * pre-existing work on the same payload.
 */
const PROMPT_INJECTION_SCAN_MAX_CHARS = 4000;

/**
 * Extracts a bounded, concatenated string of every string-valued leaf out
 * of a structured (object/array) tool result, for the same
 * `analyzePromptInjection` advisory check `applyPostCallAdvisories` already
 * runs against a plain-string `result.data` (see that method's doc
 * comment). Added by Task 5 to close a real gap: `packages/demo-soc-tools`'
 * SIEM responses are `{ events: [...] }` JSON, never a plain string, so
 * before this the prompt-injection hook never inspected them at all (see
 * `docs/ai-security-model.md`'s "Prompt-injection advisory" section and
 * `test/complete-demo.e2e-spec.ts`'s file-level doc comment).
 *
 * Bounded by `PROMPT_INJECTION_SCAN_MAX_DEPTH`/`PROMPT_INJECTION_SCAN_MAX_CHARS`
 * (see those constants' doc comments) so this synchronous walk can never
 * itself become meaningful hot-lane latency, and deliberately handles only
 * plain objects and arrays (`Array.isArray` / `typeof === 'object'`) --
 * `Map`/`Set`/class instances are out of scope, since every
 * `ToolProtocolAdapter` returns parsed JSON by construction (see that
 * interface's doc comment), and non-string leaves (numbers, booleans,
 * `null`) are skipped outright -- they can't carry injected text.
 *
 * Returns `null` when there is nothing string-shaped to inspect at all (a
 * bare number/boolean/`null` result, or an object/array with zero string
 * leaves) -- the caller skips the `analyzePromptInjection` RPC entirely in
 * that case, exactly as it already did for any non-string `result.data`
 * before this task existed.
 */
function collectStructuredInjectionText(value: unknown): string | null {
  const parts: string[] = [];
  let remaining = PROMPT_INJECTION_SCAN_MAX_CHARS;

  const visit = (node: unknown, depth: number): void => {
    if (remaining <= 0 || depth > PROMPT_INJECTION_SCAN_MAX_DEPTH) return;
    if (typeof node === 'string') {
      if (node.length === 0) return;
      const chunk = node.slice(0, remaining);
      parts.push(chunk);
      remaining -= chunk.length;
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) {
        if (remaining <= 0) break;
        visit(item, depth + 1);
      }
      return;
    }
    if (node !== null && typeof node === 'object') {
      for (const key of Object.keys(node)) {
        if (remaining <= 0) break;
        visit((node as Record<string, unknown>)[key], depth + 1);
      }
      return;
    }
    // number/boolean/null/undefined -- can't carry injected text, skip.
  };

  visit(value, 0);
  return parts.length > 0 ? parts.join('\n') : null;
}

export interface CredentialBrokerInvokeInput {
  /** Phase 9a: needed only to attribute audit events to the right tenant chain — `CredentialBrokerService` never used a raw tenant id before this (tenant isolation already comes from `tenantClient` itself). */
  tenantId: string;
  taskId: string;
  agentId: string;
  toolId: string;
  actionId: string;
  resource: string;
  params: unknown;
  /** ADR-003: the committed `Decision` this execution runs under. */
  decisionId: string;
}

/**
 * The single place a resolved tool credential ever exists in this process
 * (Section 35). `invoke`:
 *
 *   1. Loads `Tool`/`ToolAction` (`ToolRegistryService`) — throws
 *      `ToolNotFoundError`/`ToolActionNotFoundError` if either doesn't
 *      resolve (no `ToolInvocation` row is possible here: its `toolId`/
 *      `actionId` columns are real foreign keys, so there is nothing valid
 *      to reference yet).
 *   2. Confirms `Tool.enabled` — a disabled tool fails cleanly even though
 *      `AuthorizationService` already ALLOWed (tool enablement is an
 *      operational concern, not an authorization decision). Unlike step 1,
 *      both ids are known by now, so this *does* record a `FAILURE`
 *      `ToolInvocation` row before throwing `ToolDisabledError`.
 *   3. Resolves the credential via the injected `SecretProvider`
 *      (`CompositeSecretProvider` — dispatches to `EnvSecretProvider` or
 *      `OpenBaoSecretProvider` based on `Tool.credentialReference.provider`,
 *      this service never branches on it itself). The resolved value is
 *      held only in a local variable for exactly as long as step 4 takes —
 *      never logged, never assigned to any field that could end up in the
 *      `ToolInvocation` row or the returned `ToolInvocationResult`.
 *   4. Dispatches to `HttpToolAdapter`, `McpToolAdapter` or
 *      `MicrosoftToolAdapter` (ADR-0004) based on `Tool.protocol` — all
 *      three behind this same pipeline, no separate path for any protocol.
 *   5. Records a `ToolInvocation` row (`SUCCESS`/`FAILURE`, timing,
 *      `resource`, a short `errorMessage` on failure) — never the resolved
 *      credential, never a raw request/response payload (an adapter's
 *      `ToolInvocationResult.errorMessage` is already a short,
 *      credential-free summary by construction — see that interface's doc
 *      comment).
 *   6. Returns the adapter's `ToolInvocationResult` unchanged — the
 *      credential is provably not part of it under any code path in this
 *      method (see the "credential never leaks" test, which greps the
 *      actual serialized response/DB row rather than trusting this
 *      comment).
 */
@Injectable()
export class CredentialBrokerService {
  private readonly logger = new Logger(CredentialBrokerService.name);
  private readonly injectionBlockThreshold: number;

  constructor(
    private readonly toolRegistry: ToolRegistryService,
    @Inject(SECRET_PROVIDER) private readonly secretProvider: SecretProvider,
    private readonly httpAdapter: HttpToolAdapter,
    private readonly mcpAdapter: McpToolAdapter,
    private readonly auditService: AuditService,
    private readonly aiAdvisoryClient: AiAdvisoryClient,
    private readonly microsoftAdapter: MicrosoftToolAdapter,
    configService: ConfigService<AppConfig, true>,
    private readonly manarConnector: ManarConnectorService,
    private readonly handoverStore: HandoverStore,
  ) {
    this.injectionBlockThreshold = configService.get(
      'PROMPT_INJECTION_BLOCK_THRESHOLD',
      { infer: true },
    );
  }

  async invoke(
    tenantClient: TenantPrismaClient,
    input: CredentialBrokerInvokeInput,
  ): Promise<ToolInvocationResult> {
    const resolved = await this.toolRegistry.findToolAction(
      tenantClient,
      input.toolId,
      input.actionId,
    );
    if (!resolved) {
      const tool = await this.toolRegistry.findToolByName(
        tenantClient,
        input.toolId,
      );
      const notFoundReason = tool ? 'tool_action_not_found' : 'tool_not_found';
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.TOOL_INVOCATION_FAILED,
        actor: { type: 'agent', id: input.agentId },
        data: {
          taskId: input.taskId,
          decisionId: input.decisionId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
          reason: notFoundReason,
        },
      });
      if (!tool) throw new ToolNotFoundError(input.toolId);
      throw new ToolActionNotFoundError(input.toolId, input.actionId);
    }
    const { tool, action } = resolved;

    // Phase 9a: `tool.invocation.started` — the earliest point real
    // toolRowId/actionRowId exist to reference, mirroring the same
    // constraint `recordInvocation`'s own FK-backed `ToolInvocation` row
    // has always had (see step 1's early-return above, which never records
    // an operational row either, for the same reason).
    //
    // This write must succeed before anything else happens (Gate 0 finding
    // R2): it uses the throwing `record`, and a failure is a 503
    // `enforcement_dependency_unavailable` with no credential fetched and no
    // adapter contacted. A side effect with no audit trail is worse than no
    // side effect.
    await failClosed('audit-store', () =>
      this.auditService.record(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.TOOL_INVOCATION_STARTED,
        actor: { type: 'agent', id: input.agentId },
        data: {
          taskId: input.taskId,
          decisionId: input.decisionId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
        },
      }),
    );

    if (!tool.enabled) {
      await this.recordInvocation(tenantClient, input, {
        status: 'FAILURE',
        startedAt: new Date(),
        completedAt: new Date(),
        errorMessage: 'Tool is disabled',
        toolRowId: tool.id,
        actionRowId: action.id,
      });
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.TOOL_INVOCATION_FAILED,
        actor: { type: 'agent', id: input.agentId },
        data: {
          taskId: input.taskId,
          decisionId: input.decisionId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
          reason: 'tool_disabled',
        },
      });
      throw new ToolDisabledError(input.toolId);
    }

    // Phase 10b DLP before-call checkpoint: scan outbound `params` before
    // any tool contact is attempted. A severe finding blocks the call
    // outright (never creates a ToolInvocation row -- mirrors
    // AuthorizationService's own DENY, which the design spec explicitly
    // asks this to mirror, not the "tool disabled" operational-failure
    // shape above). `null` (AiAdvisoryClient unreachable/timed out/circuit
    // open) never blocks -- see DLP_BLOCKING_SEVERITIES's doc comment and
    // AiAdvisoryClient's own "never fail open, never fail closed toward
    // the caller" contract.
    const dlpBefore = await this.aiAdvisoryClient.analyzeDlp({
      content: JSON.stringify(input.params ?? null),
      tenantId: input.tenantId,
      // Phase 15a (Section 53): lets AiAdvisoryClient's residency gate
      // independently block this call to an external provider when this
      // action is RESTRICTED, regardless of the tenant's allowExternalAi
      // flag.
      classification: action.classification,
    });
    if (dlpBefore && DLP_BLOCKING_SEVERITIES.has(dlpBefore.overallSeverity)) {
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.DLP_BLOCKED,
        actor: { type: 'agent', id: input.agentId },
        data: {
          taskId: input.taskId,
          decisionId: input.decisionId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
          overallSeverity: dlpBefore.overallSeverity,
          // Redacted metadata only -- never the raw matched value (Section
          // 73, same rule Phase 9a's credential-secrecy test established
          // for tool credentials).
          findings: dlpBefore.findings.map((f) => ({
            type: f.type,
            source: f.source,
            redactedPreview: f.redactedPreview,
          })),
        },
      });
      throw new DlpBlockedError();
    }

    const startedAt = new Date();
    let result: ToolInvocationResult;
    try {
      if (isManarBuiltin(tool)) {
        // ADR-0009: Manar's own connector runs in-process on this tenant's
        // database and needs no credential.
        result = await this.manarConnector.invoke(tenantClient, input);
      } else {
        const credential = await this.secretProvider.resolve(
          tool.credentialReference,
        );
        const adapter =
          tool.protocol === 'MCP'
            ? this.mcpAdapter
            : tool.protocol === 'MICROSOFT'
              ? this.microsoftAdapter
              : this.httpAdapter;
        result = await adapter.invoke(
          tool,
          action,
          input.resource,
          input.params,
          credential,
        );
      }
    } catch (error) {
      // Credential resolution or an adapter-internal throw (never expected
      // from either adapter's own contract, which always resolves to a
      // ToolInvocationResult -- this is a defensive fallback). Logged
      // server-side only; the stored/returned message is a fixed, generic
      // string -- never the raw error, which for a credential-resolution
      // failure could in principle describe *why* (e.g. a KV path), never
      // the secret *value* itself, but there is no reason to take that
      // risk when a generic message is just as actionable operationally.
      this.logger.error(
        `Tool invocation for "${input.toolId}/${input.actionId}" failed before a result could be produced`,
        error instanceof Error ? error.stack : undefined,
      );
      result = { success: false, errorMessage: 'tool invocation failed' };
    }

    // ADR-0011: a value for the approving person never travels further than
    // this line inside the result: it goes to OpenBao or is discarded.
    const { handover, ...withoutHandover } = result;
    result = withoutHandover;
    let handoverState: string | undefined;
    if (handover && result.success) {
      handoverState = await this.storeHandover(tenantClient, input, handover);
      result = {
        ...result,
        data: { ...(result.data as object), handover: handoverState },
      };
    }

    const status = result.success
      ? 'SUCCESS'
      : result.outcomeUnknown
        ? 'UNKNOWN'
        : 'FAILURE';

    await this.recordInvocation(tenantClient, input, {
      status,
      startedAt,
      completedAt: new Date(),
      errorMessage: result.success
        ? null
        : (result.errorMessage ?? 'unknown error'),
      toolRowId: tool.id,
      actionRowId: action.id,
    });

    // Phase 9a: `data` deliberately never includes the resolved credential
    // (a hard rule — see `test/tool-gateway.e2e-spec.ts`'s existing
    // credential-secrecy scenario, extended by
    // `test/audit-retrofit.e2e-spec.ts` to grep the AuditEvent row too) nor
    // the raw request/response payload — the same conservative posture the
    // operational `ToolInvocation` row above already takes (`resource`/
    // `status`/`errorMessage` are shape/summary only).
    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      // `outcome_unknown` is the reconciliation hook: an operator (or a later
      // reconciliation job) must confirm with the tool whether it happened.
      eventType:
        status === 'SUCCESS'
          ? AUDIT_EVENT_TYPES.TOOL_INVOCATION_COMPLETED
          : status === 'UNKNOWN'
            ? AUDIT_EVENT_TYPES.TOOL_INVOCATION_OUTCOME_UNKNOWN
            : AUDIT_EVENT_TYPES.TOOL_INVOCATION_FAILED,
      actor: { type: 'agent', id: input.agentId },
      data: {
        taskId: input.taskId,
        decisionId: input.decisionId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        status,
        errorMessage: result.success ? null : (result.errorMessage ?? null),
        ...(handoverState ? { handover: handoverState } : {}),
      },
    });

    if (result.success) {
      result = await this.applyPostCallAdvisories(
        tenantClient,
        input,
        result,
        action.classification,
      );
    }

    return result;
  }

  /**
   * Phase 10b post-call advisories, run only for a *successful* tool call
   * (see docs/ai-security-model.md). Two independent checks, both against
   * the tool's own returned result, both advisory-only in the sense that
   * neither can undo the already-completed call itself:
   *
   *   1. Result DLP (ADR-0002 "Result DLP"), the same classification the
   *      LLM proxy applies to prompts (`src/common/dlp/dlp-classification.ts`):
   *      the deterministic floor runs first, in-process, then manar-ai
   *      `analyzeDlp` on the floor's PII-redacted text (`classifyDlp`).
   *      - a credential (floor shape, or a manar-ai credential-type finding)
   *        -> the whole `data` is withheld (`redactedToolResultPlaceholder`);
   *      - UAE PII -> replaced in place with `[REDACTED:<TYPE>]`, the rest
   *        of the result is returned;
   *      - manar-ai `TYPE_PII`/`TYPE_OTHER` -> the string leaf carrying it
   *        is replaced whole with `[REDACTED:PII|OTHER]`; if it cannot be
   *        located within `DLP_LOCATE_MAX_CALLS`, the result is withheld;
   *      - e-mail / UPN -> returned unchanged.
   *      Either redaction records `dlp.result_redacted` with finding types
   *      and counts (never the values).
   *   2. Prompt-injection advisory: when `result.data` is a string, runs
   *      directly against it. When it's a structured object/array (e.g.
   *      `packages/demo-soc-tools`' `{ events: [...] }` SIEM responses),
   *      Task 5's `collectStructuredInjectionText` walks it (bounded --
   *      see that function's doc comment) and, if it finds any string
   *      leaves, the same single `analyzePromptInjection` call below runs
   *      against the bounded, concatenated result instead -- still exactly
   *      one RPC call either way, never one per leaf. A result with
   *      nothing string-shaped at all (a bare number/boolean/`null`, or an
   *      object with zero string leaves) skips the call entirely, same as
   *      before Task 5. On detection, records a `prompt_injection.detected`
   *      audit event, replaces `data` with `PROMPT_INJECTION_WITHHELD` when
   *      the confidence reaches `PROMPT_INJECTION_BLOCK_THRESHOLD` (the
   *      event's `withheld` field says which), and sets a short-lived
   *      `AgentRiskFlag` for this agent
   *      (`RiskEngine` folds an active flag into `deterministicRiskScore`
   *      for this agent's *subsequent* requests -- see that class's
   *      `AGENT_RISK_FLAG_BUMP` doc comment). Runs against the *original*,
   *      pre-redaction text/structure -- detection is analysis-only and
   *      never itself returned to any caller, so there is no leak risk in
   *      analyzing the unredacted value here.
   *
   *   `null` from either `AiAdvisoryClient` call (unreachable/timed
   *   out/circuit open) is a no-op for that manar-ai check (Section 80's "AI
   *   outage does not change what's returned"). The deterministic floor in
   *   check 1 does not depend on manar-ai and still applies.
   */
  private async applyPostCallAdvisories(
    tenantClient: TenantPrismaClient,
    input: CredentialBrokerInvokeInput,
    result: ToolInvocationResult,
    /** Phase 15a (Section 53): the invoked action's own resolved `ToolAction.classification` — threaded through to both advisory calls below so `AiAdvisoryClient`'s residency gate can independently block a RESTRICTED action's data from ever reaching an external provider. */
    classification: DataClassification,
  ): Promise<ToolInvocationResult> {
    const originalData = result.data;
    let outcome = result;

    const dlp = await classifyDlp(originalData, (content) =>
      this.aiAdvisoryClient.analyzeDlp({
        content,
        tenantId: input.tenantId,
        classification,
      }),
    );
    const redactedInPlace =
      dlp.piiTypes.length > 0 ||
      Object.keys(dlp.advisoryRedactedCounts).length > 0;
    if (dlp.blocked || redactedInPlace) {
      const floorCount = Object.values(dlp.counts).reduce((a, n) => a + n, 0);
      outcome = {
        ...outcome,
        data: dlp.blocked
          ? redactedToolResultPlaceholder(
              [
                ...dlp.credentialTypes,
                ...dlp.piiTypes,
                ...dlp.blockingFindings.map((f) => f.type),
                ...dlp.unlocatedTypes,
              ],
              floorCount +
                dlp.blockingFindings.length +
                dlp.unlocatedTypes.length,
            )
          : dlp.value,
      };
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.DLP_RESULT_REDACTED,
        actor: { type: 'agent', id: input.agentId },
        data: {
          taskId: input.taskId,
          decisionId: input.decisionId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
          mode: dlp.blocked ? 'withheld' : 'redacted_in_place',
          // Types and counts only, never the matched values.
          floorFindingCounts: dlp.counts,
          advisoryRedactedCounts: dlp.advisoryRedactedCounts,
          unlocatedTypes: dlp.unlocatedTypes,
          overallSeverity: dlp.advisory?.overallSeverity,
          findings: dlp.blockingFindings.map((f) => ({
            type: f.type,
            source: f.source,
            redactedPreview: f.redactedPreview,
          })),
        },
      });
    }

    // Task 5: the plain-string case is untouched (`originalData` itself,
    // no truncation, exactly the pre-Task-5 behavior); the structured case
    // is new -- `collectStructuredInjectionText` returns `null` (skip, no
    // RPC) when there's nothing string-shaped to inspect.
    const injectionText: string | null =
      typeof originalData === 'string'
        ? originalData
        : originalData !== null && typeof originalData === 'object'
          ? collectStructuredInjectionText(originalData)
          : null;

    if (injectionText !== null) {
      const injection = await this.aiAdvisoryClient.analyzePromptInjection({
        content: injectionText,
        source: 'tool_output',
        tenantId: input.tenantId,
        classification,
      });
      if (injection && injection.detected) {
        const reason = `prompt_injection_detected:${input.toolId}/${input.actionId}`;
        // Gate 0 R5 block-and-flag: a confident detection withholds the
        // result from the agent (the call itself already happened and
        // still reports success); a weaker one only flags, as before.
        const withheld = injection.confidence >= this.injectionBlockThreshold;
        if (withheld) {
          outcome = { ...outcome, data: PROMPT_INJECTION_WITHHELD };
        }
        await this.auditService.recordSafely(tenantClient, input.tenantId, {
          eventType: AUDIT_EVENT_TYPES.PROMPT_INJECTION_DETECTED,
          actor: { type: 'agent', id: input.agentId },
          data: {
            taskId: input.taskId,
            decisionId: input.decisionId,
            toolId: input.toolId,
            actionId: input.actionId,
            resource: input.resource,
            confidence: injection.confidence,
            indicators: injection.indicators,
            explanation: injection.explanation,
            withheld,
          },
        });
        await tenantClient.agentRiskFlag.create({
          data: {
            agentId: input.agentId,
            reason,
            expiresAt: new Date(Date.now() + PROMPT_INJECTION_RISK_FLAG_TTL_MS),
          },
        });
      }
    }

    return outcome;
  }

  /**
   * ADR-0011: keeps `handover` in OpenBao for the person who approved this
   * execution, found through the decision's grant. Without an approval
   * (the policy allowed the action outright) there is no one entitled to it,
   * so it is discarded. Returns what the agent is told: where it went, never
   * the value.
   */
  private async storeHandover(
    tenantClient: TenantPrismaClient,
    input: CredentialBrokerInvokeInput,
    handover: Record<string, string>,
  ): Promise<string> {
    try {
      const decision = await tenantClient.decision.findUnique({
        where: { id: input.decisionId },
        select: { grantId: true },
      });
      const grant = decision?.grantId
        ? await tenantClient.authorizationGrant.findUnique({
            where: { id: decision.grantId },
            select: { approvalRequestId: true },
          })
        : null;
      if (!grant) {
        return 'discarded: no person approved this action, so nobody receives the value';
      }
      await this.handoverStore.put(
        input.tenantId,
        grant.approvalRequestId,
        handover,
      );
      return `held for the approving person (approval ${grant.approvalRequestId}); not given to the agent`;
    } catch (error) {
      this.logger.warn(
        `Handover for decision "${input.decisionId}" could not be stored: ${error instanceof Error ? error.name : 'unknown'}`,
      );
      return 'discarded: it could not be stored; run the action again to issue a new value';
    }
  }

  private async recordInvocation(
    tenantClient: TenantPrismaClient,
    input: CredentialBrokerInvokeInput,
    record: {
      status: 'SUCCESS' | 'FAILURE' | 'UNKNOWN';
      startedAt: Date;
      completedAt: Date;
      errorMessage: string | null;
      toolRowId: string;
      actionRowId: string;
    },
  ): Promise<void> {
    await tenantClient.toolInvocation.create({
      data: {
        taskId: input.taskId,
        agentId: input.agentId,
        toolId: record.toolRowId,
        actionId: record.actionRowId,
        resource: input.resource,
        status: record.status,
        startedAt: record.startedAt,
        completedAt: record.completedAt,
        errorMessage: record.errorMessage,
        decisionId: input.decisionId,
      },
    });
  }
}
