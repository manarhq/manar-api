import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { scopeMatches } from './rule-scope';

/** "Approve for 8 hours" (spec 4.6). */
export const ALLOW_GRANT_TTL_MS = 8 * 60 * 60 * 1000;

/** "Always allow this here" (offer) and accepted learning suggestions last a year, then ask again. */
export const ALWAYS_GRANT_TTL_MS = 365 * 24 * 60 * 60 * 1000;

/**
 * A grant belongs to exactly one device or exactly one agent. A scope with neither, or both, matches
 * nothing and cannot be created: fail closed.
 */
export type AllowGrantScope =
  | { hostId: string; agentId?: undefined }
  | { agentId: string; hostId?: undefined };

export interface AllowGrantTarget {
  toolId: string;
  actionId: string;
  resource: string;
}

function scopeWhere(
  scope: AllowGrantScope,
): { hostId: string } | { agentId: string } | null {
  if (scope.hostId && !scope.agentId) return { hostId: scope.hostId };
  if (scope.agentId && !scope.hostId) return { agentId: scope.agentId };
  return null;
}

/**
 * The tenant database is the tenant boundary (one database per tenant), so a grant created through
 * one tenant's client is invisible to every other tenant. Within a tenant it covers one device or
 * agent, one tool, one action and one exact resource string, for 8 hours.
 */
export async function createAllowGrant(
  client: Pick<TenantPrismaClient, 'approvalAllowGrant'>,
  input: {
    scope: AllowGrantScope;
    target: AllowGrantTarget;
    createdBy: string;
    sourceId: string;
    now?: Date;
    /** A longer-lived, narrow-scope grant ("always allow this here"); default is exact, 8 hours. */
    always?: { origin: 'offer' | 'learning'; pattern: string };
  },
) {
  const where = scopeWhere(input.scope);
  if (!where)
    throw new Error('an allow grant needs exactly one of hostId and agentId');
  const now = input.now ?? new Date();
  return client.approvalAllowGrant.create({
    data: {
      ...where,
      ...input.target,
      createdBy: input.createdBy,
      sourceId: input.sourceId,
      createdAt: now,
      expiresAt: new Date(
        now.getTime() +
          (input.always ? ALWAYS_GRANT_TTL_MS : ALLOW_GRANT_TTL_MS),
      ),
      ...(input.always
        ? { origin: input.always.origin, resourcePattern: input.always.pattern }
        : {}),
    },
  });
}

export async function findLiveAllowGrant(
  client: Pick<TenantPrismaClient, 'approvalAllowGrant'>,
  scope: AllowGrantScope,
  target: AllowGrantTarget,
  now: Date = new Date(),
): Promise<{ id: string; expiresAt: Date } | null> {
  const where = scopeWhere(scope);
  if (!where) return null;
  return client.approvalAllowGrant.findFirst({
    where: {
      ...where,
      toolId: target.toolId,
      actionId: target.actionId,
      resource: target.resource,
      effect: 'ALLOW',
      revokedAt: null,
      expiresAt: { gt: now },
    },
    orderBy: { expiresAt: 'desc' },
    select: { id: true, expiresAt: true },
  });
}

/**
 * A live device grant whose narrow scope (`resourcePattern`) covers this request. Looked up only
 * when a policy asks for approval and no exact grant exists, so the common path pays nothing.
 * A scope never covers a secret, a `..` climb or a command (`scopeMatches`).
 */
export async function findLivePatternGrant(
  client: Pick<TenantPrismaClient, 'approvalAllowGrant'>,
  hostId: string,
  target: AllowGrantTarget,
  now: Date = new Date(),
): Promise<{ id: string; expiresAt: Date } | null> {
  const rows = await client.approvalAllowGrant.findMany({
    where: {
      hostId,
      toolId: target.toolId,
      actionId: target.actionId,
      effect: 'ALLOW',
      revokedAt: null,
      expiresAt: { gt: now },
      resourcePattern: { not: null },
    },
    select: { id: true, expiresAt: true, resourcePattern: true },
    take: 50,
  });
  return (
    rows.find((r) =>
      scopeMatches(
        r.resourcePattern!,
        target.toolId,
        target.actionId,
        target.resource,
      ),
    ) ?? null
  );
}

/**
 * How long a block from a revoked-after-use approval lasts unless a person lifts it first.
 * ponytail: fixed 30 days; make it a workspace setting if someone asks for longer.
 */
export const BLOCK_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Revoked after use (founder decision, 3 Nov 2026): the next request for this exact action on
 * this device or agent is denied with `revoked_after_use` until a person lifts the block.
 */
export function createBlock(
  client: Pick<TenantPrismaClient, 'approvalAllowGrant'>,
  input: {
    scope: AllowGrantScope;
    target: AllowGrantTarget;
    createdBy: string;
    sourceId: string;
    now: Date;
  },
) {
  const where = scopeWhere(input.scope);
  if (!where)
    throw new Error('a block needs exactly one of hostId and agentId');
  return client.approvalAllowGrant.create({
    data: {
      ...where,
      ...input.target,
      effect: 'BLOCK',
      createdBy: input.createdBy,
      sourceId: input.sourceId,
      createdAt: input.now,
      expiresAt: new Date(input.now.getTime() + BLOCK_TTL_MS),
    },
  });
}

/** A live block for this exact action, or null. A lookup failure throws: callers fail closed. */
export function findLiveBlock(
  client: Pick<TenantPrismaClient, 'approvalAllowGrant'>,
  scope: AllowGrantScope,
  target: AllowGrantTarget,
  now: Date = new Date(),
): Promise<{ id: string } | null> {
  const where = scopeWhere(scope);
  if (!where) return Promise.resolve(null);
  return client.approvalAllowGrant.findFirst({
    where: {
      ...where,
      toolId: target.toolId,
      actionId: target.actionId,
      resource: target.resource,
      effect: 'BLOCK',
      revokedAt: null,
      expiresAt: { gt: now },
    },
    select: { id: true },
  });
}

/** Withdraws every live 8-hour grant an approval created. Returns how many. */
export async function revokeAllowGrantsFrom(
  client: Pick<TenantPrismaClient, 'approvalAllowGrant'>,
  sourceId: string,
  now: Date,
): Promise<number> {
  const { count } = await client.approvalAllowGrant.updateMany({
    where: {
      sourceId,
      effect: 'ALLOW',
      revokedAt: null,
      expiresAt: { gt: now },
    },
    data: { revokedAt: now },
  });
  return count;
}

export async function markAllowGrantUsed(
  client: Pick<TenantPrismaClient, 'approvalAllowGrant'>,
  grantId: string,
  now: Date = new Date(),
): Promise<void> {
  await client.approvalAllowGrant.update({
    where: { id: grantId },
    data: { useCount: { increment: 1 }, lastUsedAt: now },
  });
}
