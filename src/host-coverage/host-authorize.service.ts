import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  findLiveAllowGrant,
  findLiveBlock,
  findLivePatternGrant,
  markAllowGrantUsed,
} from '../approvals/allow-grants';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { PolicyEngine } from '../policy/policy-engine.service';
import { COMMAND_RISK, classifyCommand } from '../policy/command-safety';
import { resourceKindFor } from '../policy/resource-aliases';
import { HIGH_RISK_SCORE } from '../approvals/host-approval-opener.service';
import {
  canonicalAbsolute,
  pathDiffers,
  pathLinked,
  resolvedIsSecret as secretPath,
} from '../approvals/rule-scope';
import { KNOWN_HOST_TOOL_IDS, hostActionRisk } from '../tools/host-actions';
import { redactForStorage } from '../contract/redact';
import type { HostContext } from '../host-mtls/host-context';

/** `POST /host/v1/authorize`: the `/agent/v1/authorize` body without a task (a device has none). */
export const HostAuthorizeSchema = z.object({
  taskId: z.string().max(128).optional(),
  /** Who called the device's local relay (`uid:1000`, `sid:S-1-5-21-...`), as the OS reported it. */
  caller: z.string().max(128).optional(),
  toolId: z.string().min(1).max(128),
  actionId: z.string().min(1).max(128),
  resource: z.string().min(1).max(2048),
  /**
   * Where a file `resource` really points once symlinks are followed (sent by newer devices). When
   * it differs from `resource`, no folder scope is offered or applied and learning stays out.
   */
  resolvedPath: z.string().min(1).max(2048).optional(),
});
export type HostAuthorizeRequest = z.infer<typeof HostAuthorizeSchema>;

export interface HostAuthorizeDecision {
  decision: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
  reason?: string;
  riskScore?: number;
  approvalId?: string;
  expiresAt?: Date;
  /** Set when a live "Approve for 8 hours" grant turned an approval requirement into ALLOW. */
  grantId?: string;
  /**
   * Always false when the answer exists only because of a grant or learning mode: the device's
   * offline snapshot must never store it, or a withdrawn permission would keep working offline.
   */
  cacheable?: boolean;
  /** Which ask this is (`ceiling` or a policy rule); the approval and any scoped grant carry it. */
  askKey?: string;
  /** Internal: the device could not vouch for the path (no offer); stripped before the answer leaves. */
  pathLinked?: boolean;
}

/** The ask that comes from the risk ceiling: no rule matched. */
export const CEILING_ASK = 'ceiling';

/**
 * A policy ask is identified by the policy version and the exact rule that asked, so a grant made
 * for one rule never answers another, and republishing a policy ends the grants made for it.
 */
export function policyAskKey(policy: {
  policyVersionId?: string;
  matchedRule?: unknown;
}): string {
  return `p:${createHash('sha256')
    .update(
      `${policy.policyVersionId ?? ''}|${JSON.stringify(policy.matchedRule ?? null)}`,
    )
    .digest('hex')
    .slice(0, 24)}`;
}

const EFFECT_RANK = { ALLOW: 0, APPROVAL_REQUIRED: 1, DENY: 2 } as const;

/** Same as the default task ceiling for Claude Code: reads and fetches run, edits and shell ask. */
export const HOST_RISK_CEILING = 20;

/** The approvals track provides this to open a host approval; absent, APPROVAL_REQUIRED has no id. */
export const HOST_APPROVAL_OPENER = Symbol('HOST_APPROVAL_OPENER');
export interface HostApprovalOpener {
  open(
    host: HostContext,
    request: HostAuthorizeRequest,
    decision: {
      reason: string;
      riskScore: number;
      askKey?: string;
      pathLinked?: boolean;
    },
  ): Promise<{ id: string; expiresAt: Date } | null>;
}

/**
 * The decision for an action of a non-Claude AI tool on an enrolled device. Order: device
 * approved, tool in the catalogue, kill switches, the tenant's published policies (its active
 * preset), and for an action no rule matched the catalogue risk against HOST_RISK_CEILING.
 * Any failure is a DENY (fail closed). The host and tenant come from the verified certificate only.
 */
@Injectable()
export class HostAuthorizeService {
  private readonly logger = new Logger(HostAuthorizeService.name);

  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly killSwitches: KillSwitchService,
    private readonly policy: PolicyEngine,
    private readonly audit: AuditService,
    @Optional()
    @Inject(HOST_APPROVAL_OPENER)
    private readonly approvals?: HostApprovalOpener,
  ) {}

  async authorize(
    host: HostContext,
    request: HostAuthorizeRequest,
  ): Promise<HostAuthorizeDecision> {
    // The device appends the tool's session id to the caller ("uid:1000|s:<id>"); it only groups
    // events into sessions and decides nothing.
    const m = /^(.*)\|s:([A-Za-z0-9._:-]{1,64})$/.exec(request.caller ?? '');
    const caller = m ? m[1]! : (request.caller ?? null);
    const sessionId = m ? m[2]! : null;
    let result: HostAuthorizeDecision;
    let client;
    try {
      client = await this.tenants.getClient(host.tenantId);
      result = await this.decide(client, host, request);
      // What depends on where a link points is not stored by the device's offline snapshot.
      if (
        pathDiffers(
          request.toolId,
          request.actionId,
          request.resource,
          request.resolvedPath,
        )
      )
        result.cacheable = false;
    } catch (error) {
      this.logger.error(
        `host authorize failed closed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return { decision: 'DENY', reason: 'enforcement_dependency_unavailable' };
    }
    if (result.decision === 'APPROVAL_REQUIRED' && this.approvals) {
      try {
        const a = await this.approvals.open(host, request, {
          reason: result.reason ?? 'policy_requires_approval',
          riskScore: result.riskScore ?? 0,
          askKey: result.askKey,
          pathLinked: result.pathLinked,
        });
        if (a) result = { ...result, approvalId: a.id, expiresAt: a.expiresAt };
      } catch (error) {
        this.logger.warn(
          `host approval could not be opened: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    if (result.grantId) {
      // Counting a use must not change the answer; the audit record below is what matters.
      await markAllowGrantUsed(client, result.grantId).catch((error: unknown) =>
        this.logger.error(
          `could not count use of allow grant: ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
      await this.audit.recordSafely(client, host.tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_USED,
        actor: { type: 'system', id: `host:${host.hostId}` },
        data: {
          grantId: result.grantId,
          hostId: host.hostId,
          toolId: request.toolId,
          actionId: request.actionId.toLowerCase(),
          resource: redactForStorage(request.resource),
        },
      });
    }
    // The audit record is the evidence of governance: no record, no ALLOW. The command is kept
    // redacted (secrets, tokens, URL credentials and queries, home folders): the Sessions view
    // shows it, and secret values are never stored. The decision above used the real one.
    const recorded = await this.audit.recordSafely(client, host.tenantId, {
      eventType: AUDIT_EVENT_TYPES.HOST_ACTION_DECIDED,
      actor: { type: 'system', id: `host:${host.hostId}` },
      data: {
        hostId: host.hostId,
        toolId: request.toolId,
        actionId: request.actionId,
        resource: redactForStorage(request.resource),
        ...(request.resolvedPath
          ? { resolvedPath: redactForStorage(request.resolvedPath) }
          : {}),
        decision: result.decision,
        reason: result.reason ?? null,
        riskScore: result.riskScore ?? null,
        approvalId: result.approvalId ?? null,
        caller,
        sessionId,
      },
    });
    if (!recorded && result.decision === 'ALLOW') {
      return { decision: 'DENY', reason: 'enforcement_dependency_unavailable' };
    }
    delete result.pathLinked;
    return result;
  }

  private async decide(
    client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    host: HostContext,
    request: HostAuthorizeRequest,
  ): Promise<HostAuthorizeDecision> {
    if (host.status !== 'APPROVED')
      return { decision: 'DENY', reason: 'host_not_approved' };
    if (!KNOWN_HOST_TOOL_IDS.includes(request.toolId))
      return { decision: 'DENY', reason: 'unknown_tool' };
    const actionId = request.actionId.toLowerCase();
    const catalogue = hostActionRisk(request.toolId, actionId);
    if (catalogue === null)
      return { decision: 'DENY', reason: 'unknown_action' };
    // A clearly safe command (read-only, or the project's own test/lint/build) scores below the
    // high-risk line instead of 70. Policy rules, secrets and the kill switches still apply first.
    const safe =
      resourceKindFor(request.toolId, actionId) === 'command'
        ? classifyCommand(request.resource)
        : null;
    const scored = safe ? Math.min(catalogue, COMMAND_RISK[safe]) : catalogue;
    // The real target of a link is a secret (`docs -> ~/.ssh`): high risk, console only. This only
    // ever restricts; the policy still sees the path that was asked for.
    const base = resolvedIsSecret(request, actionId)
      ? Math.max(scored, HIGH_RISK_SCORE)
      : scored;

    const kill = await this.killSwitches.checkAll(client, host.tenantId, {
      agentId: host.hostId,
      toolId: request.toolId,
    });
    if (kill.killed)
      return { decision: 'DENY', reason: kill.reason ?? 'kill_switch' };

    // Revoked after use (3 Nov 2026): refused until a person lifts the block.
    if (
      await findLiveBlock(
        client,
        { hostId: host.hostId },
        { toolId: request.toolId, actionId, resource: request.resource },
      )
    )
      return { decision: 'DENY', reason: 'revoked_after_use' };

    // Grants (spec 4.6): the exact "Approve for 8 hours" grant is read here, before the policy runs;
    // a scoped "always allow here" grant is read only when something asks. Either only satisfies an
    // approval requirement below. A policy DENY and the kill switches above are never overridden.
    const target = {
      toolId: request.toolId,
      actionId,
      resource: request.resource,
    };
    // A link: an exact grant answers it only if it was made for the same real target, and a
    // plain grant (made for the file itself) never does.
    const differs = pathDiffers(
      request.toolId,
      actionId,
      request.resource,
      request.resolvedPath,
    );
    const resolvedKey = differs
      ? canonicalAbsolute(request.resolvedPath!)
      : null;
    const exact =
      differs && resolvedKey === null
        ? null
        : await findLiveAllowGrant(
            client,
            { hostId: host.hostId },
            target,
            undefined,
            resolvedKey,
          );
    // A narrow "always allow here" scope is looked up only if something asks (below).
    // A grant made for one ask never answers another (a grant without a key is an older one).
    // A path that is a link to somewhere else gets no scope, offered or applied: only the exact one.
    const linked = pathLinked(
      request.toolId,
      actionId,
      request.resource,
      request.resolvedPath,
    );
    let grant: { id: string } | null = null;
    const scoped = async (askKey: string) => {
      grant =
        exact && (!exact.askKey || exact.askKey === askKey)
          ? exact
          : linked
            ? null
            : await findLivePatternGrant(client, host.hostId, target, askKey);
      return grant;
    };
    let policy = await this.policy.evaluate(client, host.tenantId, {
      toolId: request.toolId,
      actionId,
      resource: request.resource,
    });
    // A link: ask the policy again about where the path really points and keep the stricter
    // answer (DENY, then APPROVAL_REQUIRED, then ALLOW). Rules and presets are written for the
    // path a tool names, and a "run everything else" rule would otherwise let `docs -> ~/.ssh`
    // through. Restriction only: the answer for the requested path is never loosened.
    let targetUnmatched = false;
    // A secret target asks whatever rule matched (the raise to the console-only line is in `base`).
    const secretTarget = resolvedIsSecret(request, actionId);
    if (differs) {
      const real = await this.policy.evaluate(client, host.tenantId, {
        toolId: request.toolId,
        actionId,
        resource: request.resolvedPath!,
      });
      targetUnmatched = !real.matchedRule;
      // On a tie that asks, the target's rule (and so its ask key) is the one that counts.
      if (
        EFFECT_RANK[real.effect] > EFFECT_RANK[policy.effect] ||
        (real.effect === 'APPROVAL_REQUIRED' &&
          policy.effect === 'APPROVAL_REQUIRED')
      )
        policy = real;
    }
    if (policy.effect === 'DENY') {
      return {
        decision: 'DENY',
        reason: policy.failureReason
          ? 'policy_evaluation_failed'
          : 'policy_denied',
      };
    }
    if (policy.effect === 'APPROVAL_REQUIRED') {
      const askKey = policyAskKey(policy);
      if (await scoped(askKey))
        return {
          decision: 'ALLOW',
          riskScore: base,
          grantId: grant!.id,
          cacheable: false,
        };
      return {
        decision: 'APPROVAL_REQUIRED',
        reason: 'policy_requires_approval',
        riskScore: base,
        askKey,
        pathLinked: linked,
      };
    }
    // The risk ceiling applies when nothing matched, and also when the link's name matched a rule
    // but its real target matched none.
    if (
      (!policy.matchedRule || targetUnmatched || secretTarget) &&
      base > HOST_RISK_CEILING
    ) {
      if (await scoped(CEILING_ASK))
        return {
          decision: 'ALLOW',
          riskScore: base,
          grantId: grant!.id,
          cacheable: false,
        };
      return {
        decision: 'APPROVAL_REQUIRED',
        reason: 'risk_ceiling_exceeded',
        riskScore: base,
        askKey: CEILING_ASK,
        pathLinked: linked,
      };
    }
    return { decision: 'ALLOW', riskScore: base };
  }
}

function resolvedIsSecret(
  request: { toolId: string; resolvedPath?: string },
  actionId: string,
): boolean {
  return (
    request.resolvedPath !== undefined &&
    secretPath(request.toolId, actionId, request.resolvedPath)
  );
}
