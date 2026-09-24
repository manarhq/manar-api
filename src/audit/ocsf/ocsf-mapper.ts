import { AUDIT_EVENT_TYPES } from '../audit-event-types';
import {
  OCSF_SCHEMA_VERSION,
  OcsfActor,
  OcsfMappingResult,
  OcsfMetadata,
  OcsfUser,
} from './ocsf-types';

/** The minimal shape of an `AuditEvent` this mapper needs — matches `AuditEventRecord`/a Prisma `AuditEvent` row equally well. */
export interface MappableAuditEvent {
  id: string;
  eventType: string;
  correlationId: string;
  actor: unknown;
  timestamp: Date | string;
  data: unknown;
}

const METADATA: OcsfMetadata = {
  version: OCSF_SCHEMA_VERSION,
  product: { name: 'Manar', vendor_name: 'Manar' },
};

/**
 * Phase 9b (Section 50). Transforms a Manar `AuditEvent` into its OCSF
 * v1.9.0 representation for the event types this codebase has genuinely
 * evaluated as a good fit, and returns a clearly-labeled `{ mapped: false
 * }` result (never a forced/fake mapping) for every other type. See
 * `docs/ocsf-mapping.md` for the full rationale behind exactly these three
 * classes and exactly this coverage boundary.
 *
 * Deliberately a pure function (`AuditEvent` in, `OcsfMappingResult` out)
 * — not itself an indexed/stored representation this phase. OpenSearch
 * indexes the Manar-native `AuditEvent` shape (`OpenSearchIndexService`);
 * this mapper is the reusable foundation a *future* phase's OCSF-shaped
 * SIEM export would call, not the delivery mechanism itself (explicitly
 * out of scope this phase).
 */
export function mapAuditEventToOcsf(
  event: MappableAuditEvent,
): OcsfMappingResult {
  const timeMs = new Date(event.timestamp).getTime();
  const actor = toActor(event.actor);
  const data = isRecord(event.data) ? event.data : {};

  switch (event.eventType) {
    case AUDIT_EVENT_TYPES.AGENT_ENROLLED:
      return {
        mapped: true,
        ocsf: {
          class_uid: 3002,
          class_name: 'Authentication',
          category_uid: 3,
          category_name: 'Identity & Access Management',
          activity_id: 1,
          activity_name: 'Logon',
          type_uid: 3002_01,
          severity_id: 1,
          status_id: 1,
          status: 'Success',
          time: timeMs,
          metadata: METADATA,
          user: toUser(event.actor),
          actor,
          message: `Agent "${actor.user.uid}" completed enrollment (obtained a working mTLS certificate)`,
          unmapped: pick(data, ['identifier', 'certificateSerialNumber']),
        },
      };

    case AUDIT_EVENT_TYPES.AGENT_ENROLLMENT_FAILED:
      return {
        mapped: true,
        ocsf: {
          class_uid: 3002,
          class_name: 'Authentication',
          category_uid: 3,
          category_name: 'Identity & Access Management',
          activity_id: 1,
          activity_name: 'Logon',
          type_uid: 3002_01,
          severity_id: 2,
          status_id: 2,
          status: 'Failure',
          time: timeMs,
          metadata: METADATA,
          user: toUser(event.actor),
          actor,
          message: `Agent enrollment attempt failed`,
          unmapped: pick(data, ['reason', 'identifier']),
        },
      };

    case AUDIT_EVENT_TYPES.AGENT_REVOKED:
      return {
        mapped: true,
        ocsf: {
          class_uid: 3002,
          class_name: 'Authentication',
          category_uid: 3,
          category_name: 'Identity & Access Management',
          activity_id: 2,
          activity_name: 'Logoff',
          type_uid: 3002_02,
          severity_id: 2,
          status_id: 1,
          status: 'Success',
          time: timeMs,
          metadata: METADATA,
          user: toUser(event.actor),
          actor,
          message: `Agent's certificate was revoked — it can no longer authenticate`,
          unmapped: pick(data, ['agentId', 'reason', 'serialNumber']),
        },
      };

    case AUDIT_EVENT_TYPES.AUTHORIZATION_ALLOWED:
    case AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED:
    case AUDIT_EVENT_TYPES.AUTHORIZATION_PENDING_APPROVAL: {
      const statusId =
        event.eventType === AUDIT_EVENT_TYPES.AUTHORIZATION_ALLOWED
          ? 1
          : event.eventType === AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED
            ? 2
            : 0;
      const status =
        statusId === 1 ? 'Success' : statusId === 2 ? 'Failure' : 'Unknown';
      const privilege = [data.toolId, data.actionId]
        .filter((part): part is string => typeof part === 'string')
        .join(':');
      return {
        mapped: true,
        ocsf: {
          class_uid: 3003,
          class_name: 'Authorize Session',
          category_uid: 3,
          category_name: 'Identity & Access Management',
          activity_id: 1,
          activity_name: 'Assign Privileges',
          type_uid: 3003_01,
          severity_id: statusId === 2 ? 2 : 1,
          status_id: statusId,
          status,
          time: timeMs,
          metadata: METADATA,
          user: toUser(event.actor),
          actor,
          privileges: privilege ? [privilege] : [],
          session: {
            uid: typeof data.taskId === 'string' ? data.taskId : 'unknown',
          },
          message: `Authorization decision "${status}" for task/tool/action`,
          // Manar's underlying decision inputs have no OCSF equivalent
          // field (risk score, matched policy version, denial reason,
          // task risk ceiling, raw OpenFGA booleans) — carried verbatim in
          // `unmapped` rather than repurposing an unrelated official
          // field. See docs/ocsf-mapping.md.
          unmapped: pick(data, [
            'taskId',
            'toolId',
            'actionId',
            'resource',
            'reason',
            'riskScore',
            'policyVersionId',
            'reasonCodes',
            'riskCeiling',
          ]),
        },
      };
    }

    case AUDIT_EVENT_TYPES.TOOL_INVOCATION_STARTED:
    case AUDIT_EVENT_TYPES.TOOL_INVOCATION_COMPLETED:
    case AUDIT_EVENT_TYPES.TOOL_INVOCATION_FAILED: {
      const statusId =
        event.eventType === AUDIT_EVENT_TYPES.TOOL_INVOCATION_COMPLETED
          ? 1
          : event.eventType === AUDIT_EVENT_TYPES.TOOL_INVOCATION_FAILED
            ? 2
            : 0;
      const status =
        statusId === 1 ? 'Success' : statusId === 2 ? 'Failure' : 'Unknown';
      return {
        mapped: true,
        ocsf: {
          class_uid: 6003,
          class_name: 'API Activity',
          category_uid: 6,
          category_name: 'Application Activity',
          // Deliberately `activity_id: 0` (Unknown), never guessed as
          // Create/Read/Update/Delete — the audit event's own `data`
          // never carries the invoked ToolAction's mutating/destructive
          // flags (Section 46's credential-secrecy-adjacent minimalism —
          // see docs/audit-chain.md's "tool invocation" retrofit note), so
          // there is no reliable signal here to pick a *specific* CRUD
          // activity_id from without guessing. See docs/ocsf-mapping.md.
          activity_id: 0,
          activity_name: 'Unknown',
          type_uid: 6003_00,
          severity_id: statusId === 2 ? 3 : 1,
          status_id: statusId,
          status,
          time: timeMs,
          metadata: METADATA,
          actor,
          api: {
            operation:
              typeof data.actionId === 'string' ? data.actionId : 'unknown',
            service: {
              name: typeof data.toolId === 'string' ? data.toolId : 'unknown',
            },
          },
          resources: [
            {
              uid:
                typeof data.resource === 'string' ? data.resource : 'unknown',
            },
          ],
          message: `Tool invocation "${status}"`,
          unmapped: pick(data, [
            'taskId',
            'toolId',
            'actionId',
            'resource',
            'errorMessage',
          ]),
        },
      };
    }

    default:
      return {
        mapped: false,
        eventType: event.eventType,
        reason: unmappedReason(event.eventType),
      };
  }
}

/**
 * Documents *why* each uncovered `eventType` has no good OCSF v1.9.0 fit
 * — Section 50's "clearly-labeled Manar-native shape... document that gap
 * rather than inventing a fake mapping." See `docs/ocsf-mapping.md` for
 * the full table.
 */
function unmappedReason(eventType: string): string {
  switch (eventType) {
    case AUDIT_EVENT_TYPES.TASK_CREATED:
    case AUDIT_EVENT_TYPES.TASK_REVOKED:
    case AUDIT_EVENT_TYPES.TASK_DELEGATED:
      return 'Manar task/delegation grants have no OCSF equivalent — OCSF has no notion of a time/execution-bounded, sub-delegable authority grant to a non-human principal; forcing this into Authorize Session (which models privileges on an authenticated *session*, not a standalone grant object) would misrepresent it.';
    case AUDIT_EVENT_TYPES.APPROVAL_REQUESTED:
    case AUDIT_EVENT_TYPES.APPROVAL_APPROVED:
    case AUDIT_EVENT_TYPES.APPROVAL_DENIED:
    case AUDIT_EVENT_TYPES.APPROVAL_GRANT_ISSUED:
    case AUDIT_EVENT_TYPES.APPROVAL_GRANT_REDEEMED:
    case AUDIT_EVENT_TYPES.APPROVAL_GRANT_REJECTED:
      return "OCSF has no human-approval-workflow class in v1.9.0 (nothing under Identity & Access Management or elsewhere models a pending request awaiting a second human's decision) — no existing class fits without inventing semantics OCSF doesn't define.";
    case AUDIT_EVENT_TYPES.POLICY_PUBLISHED:
      return 'OCSF v1.9.0 has no policy-authoring/publication class — the closest candidates (e.g. classes under Application Activity) model runtime API calls, not versioned governance-document lifecycle events.';
    case AUDIT_EVENT_TYPES.AUDIT_RETENTION_EXECUTED:
      return "Manar's own audit-chain retention/anchoring run is infrastructure self-audit with no real-world OCSF analog (it is not a security event about an external actor at all).";
    default:
      return `No OCSF v${OCSF_SCHEMA_VERSION} class was evaluated as a genuine fit for this event type.`;
  }
}

function toActor(rawActor: unknown): OcsfActor {
  return { user: toUser(rawActor) };
}

function toUser(rawActor: unknown): OcsfUser {
  if (
    isRecord(rawActor) &&
    typeof rawActor.id === 'string' &&
    typeof rawActor.type === 'string'
  ) {
    return { uid: rawActor.id, type: rawActor.type };
  }
  return { uid: 'unknown', type: 'unknown' };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pick(
  data: Record<string, unknown>,
  keys: string[],
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    if (key in data && data[key] !== undefined) {
      result[key] = data[key];
    }
  }
  return result;
}
