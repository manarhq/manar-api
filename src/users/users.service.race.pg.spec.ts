import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MembershipService } from '../auth/membership.service';
import { AuthCache } from '../database/auth-cache.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { EnvSecretProvider } from '../database/env-secret-provider';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { UsersService } from './users.service';

/** Real Postgres (the control DB all migrations are applied to). */
const url = process.env.CONTROL_DATABASE_URL;
describe.skipIf(!url)('role grant and revoke race (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const issuer = 'https://kc.test/realms/manar';
  let tenantId: string;

  const client = (subject: string) =>
    ({
      userProfile: {
        findUnique: () =>
          Promise.resolve({
            id: 'u1',
            keycloakSubject: subject,
            email: 'e@x.test',
            displayName: 'T',
            createdAt: new Date(),
            lastSeenAt: new Date(),
          }),
      },
    }) as never;
  const svc = new UsersService(
    { recordSafely: () => Promise.resolve() } as never,
    control,
  );
  const base = {
    issuer,
    targetUserId: 'u1',
    grantedByUserId: 'a',
    grantedByRoles: ['TENANT_OWNER'] as never,
    revokedByUserId: 'a',
    revokedByRoles: ['TENANT_OWNER'] as never,
  };

  beforeAll(async () => {
    await control.$connect();
    tenantId = (
      await control.tenant.create({
        data: {
          slug: `race-${randomUUID().slice(0, 8)}`,
          name: 'race',
          kind: 'COMPANY',
          status: 'ACTIVE',
        },
      })
    ).id;
  });
  afterAll(async () => {
    await control.membership.deleteMany({ where: { tenantId } });
    await control.tenant.deleteMany({ where: { id: tenantId } });
    await control.$disconnect();
  });

  it('a revoke racing a grant ends consistent: the revoked role never comes back, the granted one is never lost', async () => {
    for (let i = 0; i < 25; i++) {
      const subject = `sub-${i}`;
      await control.membership.create({
        data: {
          issuer,
          subject,
          tenantId,
          role: 'AUDITOR',
          extraRoles: ['SOC_OPERATOR'],
          status: 'ACTIVE',
        },
      });
      await Promise.all([
        svc.revokeRole(client(subject), {
          ...base,
          tenantId,
          role: 'SOC_OPERATOR',
        }),
        svc.grantRole(client(subject), {
          ...base,
          tenantId,
          role: 'DEVELOPER',
        }),
      ]);
      const m = await control.membership.findUniqueOrThrow({
        where: {
          issuer_subject_tenantId: { issuer, subject, tenantId },
        },
      });
      expect([m.role, ...m.extraRoles].sort()).toEqual([
        'AUDITOR',
        'DEVELOPER',
      ]);
    }
  }, 60_000);

  it('a revoked role and a suspended workspace stop resolving at once, not after the 30 s TTL', async () => {
    const cache = new AuthCache();
    const memberships = new MembershipService(control, cache);
    const cachedUsers = new UsersService(
      { recordSafely: () => Promise.resolve() } as never,
      control,
      cache,
    );
    const manager = new TenantDatabaseManager(
      control,
      {
        get: (k: string) =>
          ({
            TENANT_DB_CLIENT_CACHE_MAX: 5,
            TENANT_DB_CLIENT_IDLE_TTL_MS: 60_000,
            TENANT_DB_CLIENT_REVALIDATE_MS: 5000,
          })[k],
      } as never,
      new EnvSecretProvider(),
      cache,
    );
    const subject = 'sub-cache';
    await control.membership.create({
      data: {
        issuer,
        subject,
        tenantId,
        role: 'AUDITOR',
        extraRoles: ['SOC_OPERATOR'],
        status: 'ACTIVE',
      },
    });
    const resolve = () =>
      memberships.resolveActive({
        issuer,
        subject,
        requestedTenantId: tenantId,
      });
    expect((await resolve()).roles.sort()).toEqual(['AUDITOR', 'SOC_OPERATOR']);

    await cachedUsers.revokeRole(client(subject), {
      ...base,
      tenantId,
      role: 'SOC_OPERATOR',
    });
    expect((await resolve()).roles).toEqual(['AUDITOR']);

    await manager.suspendTenant(tenantId);
    await expect(resolve()).rejects.toThrow('Workspace not available');
    await manager.resumeTenant(tenantId);
    expect((await resolve()).roles).toEqual(['AUDITOR']);
    await manager.onModuleDestroy();
  });
});
