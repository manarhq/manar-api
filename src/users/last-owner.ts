import type { Prisma } from '../generated/control-client/client';
import type { ControlPrismaService } from '../database/control-prisma.service';
import { LastOwnerError } from './users.errors';

type Db = Pick<ControlPrismaService, 'membership'>;

/** Who is being removed from the workspace's owners (a sign-in `sub` is only unique per issuer). */
export interface OwnerRef {
  issuer: string;
  subject: string;
}

/** ACTIVE members who hold TENANT_OWNER, as primary or extra role, other than `except`. */
export function otherOwnersWhere(
  tenantId: string,
  except: OwnerRef,
): Prisma.MembershipWhereInput {
  return {
    tenantId,
    status: 'ACTIVE',
    NOT: { issuer: except.issuer, subject: except.subject },
    OR: [{ role: 'TENANT_OWNER' }, { extraRoles: { has: 'TENANT_OWNER' } }],
  };
}

/** Read-only check (no lock): is there another active owner right now? */
export async function hasAnotherOwner(
  db: Db,
  tenantId: string,
  except: OwnerRef,
): Promise<boolean> {
  return (
    (await db.membership.count({ where: otherOwnersWhere(tenantId, except) })) >
    0
  );
}

/**
 * Runs `fn` in a transaction holding the per-workspace advisory lock `owners:<tenantId>`: the one
 * lock for everything that derives a role set from a membership (grant, every revoke) and for the
 * last-owner count. `fn` must re-read the membership it changes through `tx`, after the lock.
 */
export async function withWorkspaceLock<T>(
  control: ControlPrismaService,
  tenantId: string,
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  return control.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`owners:${tenantId}`}))`;
    return fn(tx);
  });
}

/**
 * Takes `owner` out of the workspace's owners (a role revoke, or removing the member) only if
 * another active owner remains. Lock, count and write are one transaction under the per-workspace
 * advisory lock `owners:<tenantId>`, so two owners removing each other at the same moment cannot
 * both pass: the second one waits, then sees one owner left and gets {@link LastOwnerError}.
 */
export async function withOwnerLock<T>(
  control: ControlPrismaService,
  tenantId: string,
  owner: OwnerRef,
  write: (tx: Db) => Promise<T>,
): Promise<T> {
  return withWorkspaceLock(control, tenantId, async (tx) => {
    if (!(await hasAnotherOwner(tx, tenantId, owner))) {
      throw new LastOwnerError();
    }
    return write(tx);
  });
}
