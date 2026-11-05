import 'dotenv/config';
import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { LastOwnerError } from '../src/users/users.errors';
import { UsersService } from '../src/users/users.service';
import { fakeConfigService } from './support/audit-test-config';

const ISSUER = 'https://kc.test/realms/manar';

/**
 * The last active TENANT_OWNER can never lose the role, even when two owners revoke each other at
 * the same moment (real Postgres, the per-workspace advisory lock).
 */
describe('last owner (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  const provisioned: { tenantId: string; databaseName: string }[] = [];
  const audits: { eventType: string }[] = [];
  let users: UsersService;

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    const audit = {
      recordSafely: (_c: unknown, _t: string, e: { eventType: string }) => {
        audits.push(e);
        return Promise.resolve(undefined);
      },
    };
    // Widen the window between "count the other owners" and "write": a pause after each count, so
    // without the lock both revokes would pass the check.
    const slowCount = new Proxy(control, {
      get(target, prop, recv) {
        if (prop !== '$transaction')
          return Reflect.get(target, prop, recv) as unknown;
        return (fn: (tx: unknown) => Promise<unknown>) =>
          target.$transaction((tx) =>
            fn(
              new Proxy(tx, {
                get(t, p) {
                  if (p !== 'membership') return Reflect.get(t, p) as unknown;
                  return new Proxy(t.membership, {
                    get(m, q) {
                      if (q !== 'count') return Reflect.get(m, q) as unknown;
                      return async (...a: unknown[]) => {
                        const n = await (
                          m.count as (...x: unknown[]) => Promise<number>
                        )(...a);
                        await new Promise((r) => setTimeout(r, 400));
                        return n;
                      };
                    },
                  });
                },
              }),
            ),
          );
      },
    });
    users = new UsersService(audit as never, slowCount);
  }, 60_000);

  afterAll(async () => {
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      await pg.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await pg.end();
      await control.membership.deleteMany({ where: { tenantId } });
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  async function workspace(owners: number) {
    const t = await manager.provisionTenant({
      slug: `own-${randomUUID().slice(0, 8)}`,
      name: 'Owners',
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const people: { id: string; subject: string }[] = [];
    for (let i = 0; i < owners; i++) {
      const subject = `owner-${i}-${randomUUID().slice(0, 6)}`;
      const p = await client.userProfile.create({
        data: {
          keycloakSubject: subject,
          email: `${subject}@x.test`,
          displayName: subject,
        },
      });
      await control.membership.create({
        data: {
          issuer: ISSUER,
          subject,
          tenantId: t.id,
          role: 'TENANT_OWNER',
          status: 'ACTIVE',
        },
      });
      people.push({ id: p.id, subject });
    }
    const revoke = (targetId: string, byId: string) =>
      users.revokeRole(client, {
        tenantId: t.id,
        issuer: ISSUER,
        targetUserId: targetId,
        role: 'TENANT_OWNER',
        revokedByUserId: byId,
        revokedByRoles: ['TENANT_OWNER'],
      });
    const activeOwners = () =>
      control.membership.count({
        where: { tenantId: t.id, status: 'ACTIVE', role: 'TENANT_OWNER' },
      });
    return { people, revoke, activeOwners };
  }

  it('two owners revoking each other in parallel: exactly one is refused, one owner is left', async () => {
    const w = await workspace(2);
    const [a, b] = w.people as [
      (typeof w.people)[number],
      (typeof w.people)[number],
    ];
    audits.length = 0;
    const results = await Promise.allSettled([
      w.revoke(b.id, a.id),
      w.revoke(a.id, b.id),
    ]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const refused = results.filter((r) => r.status === 'rejected');
    expect(refused).toHaveLength(1);
    expect((refused[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      LastOwnerError,
    );
    expect(await w.activeOwners()).toBe(1);
    expect(audits.map((e) => e.eventType).sort()).toEqual([
      'user.role_revoke_refused',
      'user.role_revoked',
    ]);
  }, 30_000);

  it('the only owner cannot revoke their own role', async () => {
    const w = await workspace(1);
    await expect(
      w.revoke(w.people[0]!.id, w.people[0]!.id),
    ).rejects.toBeInstanceOf(LastOwnerError);
    expect(await w.activeOwners()).toBe(1);
  }, 30_000);
});
