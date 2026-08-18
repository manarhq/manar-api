import { createHash } from 'node:crypto';

/**
 * OpenFGA object/user identifiers are `type:id` strings, split on the
 * *first* colon only — but the `id` portion itself must not contain a
 * colon at all (confirmed empirically against a real local OpenFGA server
 * while building this model: `doc:tenant-1:file1` is rejected as
 * "malformed", `doc:tenant-1_file1` is accepted). Every helper below joins
 * multi-part identifiers (tenant + entity IDs) with `_` for exactly this
 * reason — UUIDs already use `-`, so `_` can't collide with one.
 *
 * `toolId`/`actionId` are validated elsewhere (see tasks.validation.ts) to
 * a safe slug-like charset, so they're used verbatim here for
 * readability/debuggability. `resource` patterns are arbitrary
 * caller-supplied strings (URLs, file paths, ...) that could contain
 * anything — including a literal `:` — so those are hashed into a fixed,
 * always-valid identifier instead of validated/escaped.
 */

function shortHash(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Full `type:id` OpenFGA object identifier for a tenant-scoped agent. */
export function agentObjectId(tenantId: string, agentId: string): string {
  return `agent:${tenantId}_${agentId}`;
}

/** Full `type:id` OpenFGA object identifier for a tenant-scoped task. */
export function taskObjectId(tenantId: string, taskId: string): string {
  return `task:${tenantId}_${taskId}`;
}

/** Full `type:id` OpenFGA object identifier for a tenant-scoped tool. */
export function toolObjectId(tenantId: string, toolId: string): string {
  return `tool:${tenantId}_${toolId}`;
}

/** Full `type:id` OpenFGA object identifier for a tenant-scoped tool action. */
export function toolActionObjectId(
  tenantId: string,
  toolId: string,
  actionId: string,
): string {
  return `tool_action:${tenantId}_${toolId}_${actionId}`;
}

/**
 * Full `type:id` OpenFGA object identifier for a tenant-scoped resource
 * selector. `pattern` is hashed (see module doc comment) — never used
 * verbatim, since it's arbitrary caller-supplied text.
 */
export function resourceObjectId(
  tenantId: string,
  toolId: string,
  pattern: string,
): string {
  return `resource:${tenantId}_${toolId}_${shortHash(pattern)}`;
}

/**
 * Full `type:id` OpenFGA object identifier for a single grant — the
 * synthetic per-(task, toolId, actionId, resource-pattern-or-"*") object
 * `AuthorizationService` calls `check()` against directly (see
 * src/authorization/model/manar.fga's doc comment). Deterministic: the
 * caller never needs to look this ID up, only recompute it from the same
 * inputs — both `TaskGrantSyncService` (write time) and
 * `AuthorizationService` (check time) call this same function.
 */
export function grantObjectId(
  tenantId: string,
  taskId: string,
  toolId: string,
  actionId: string,
  resourcePattern: string,
): string {
  return `grant:${shortHash([tenantId, taskId, toolId, actionId, resourcePattern].join('|'))}`;
}

/** The sentinel `allowedResourceSelectors` pattern meaning "any resource for this tool action" — see docs/authorization-model.md's known-limitation note on glob/prefix matching being out of scope this phase. */
export const ANY_RESOURCE_PATTERN = '*';
