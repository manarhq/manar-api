/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument -- fakes */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { KeycloakAdminClient } from '../../keycloak/keycloak-admin.client';
import {
  MembershipsGrantCommand,
  MembershipsMigrateCommand,
} from './memberships.command';

const ISSUER = 'https://auth.test/realms/acme';

function make(members: Record<string, string[]>, existing: string[] = []) {
  const created: any[] = [];
  const control = {
    tenant: {
      findMany: vi.fn().mockResolvedValue([
        {
          id: 't1',
          slug: 'acme',
          keycloakRealm: 'acme',
          keycloakIssuerUrl: `${ISSUER}/`,
        },
      ]),
    },
    membership: {
      findUnique: vi.fn(({ where }: any) =>
        Promise.resolve(
          existing.includes(where.issuer_subject_tenantId.subject)
            ? { id: 'x' }
            : null,
        ),
      ),
      create: vi.fn(({ data }: any) => {
        created.push(data);
        return Promise.resolve(data);
      }),
    },
  };
  const keycloak = {
    listRealmRoleMemberIds: vi.fn((_realm: string, role: string) => {
      if (members.__fail) return Promise.reject(new Error('keycloak down'));
      return Promise.resolve(
        Object.entries(members)
          .filter(([, roles]) => roles.includes(role))
          .map(([sub]) => sub),
      );
    }),
  };
  return {
    cmd: new MembershipsMigrateCommand(control as never, keycloak as never),
    created,
    control,
    keycloak,
  };
}

afterEach(() => {
  process.exitCode = 0;
});

describe('memberships:migrate-from-realms', () => {
  it('reads the roles users hold in Keycloak now and keeps every role of a multi-role user', async () => {
    const { cmd, created, keycloak } = make({
      alice: ['AUDITOR', 'SECURITY_ADMIN'],
      bob: ['READ_ONLY'],
    });
    await cmd.run([]);
    expect(keycloak.listRealmRoleMemberIds).toHaveBeenCalledWith(
      'acme',
      'AUDITOR',
    );
    const alice = created.find((c) => c.subject === 'alice');
    expect(alice).toMatchObject({
      issuer: ISSUER,
      tenantId: 't1',
      role: 'SECURITY_ADMIN',
      extraRoles: ['AUDITOR'],
      status: 'ACTIVE',
    });
    expect(created.find((c) => c.subject === 'bob')).toMatchObject({
      role: 'READ_ONLY',
      extraRoles: [],
    });
    expect(process.exitCode).toBe(0);
  });

  it('never overwrites an existing Membership (idempotent re-run)', async () => {
    const { cmd, created } = make({ alice: ['AUDITOR'] }, ['alice']);
    await cmd.run([]);
    expect(created).toEqual([]);
  });

  it('fails the run when Keycloak cannot be read, with no fallback to old data', async () => {
    const { cmd, created } = make({ __fail: [] });
    await cmd.run([]);
    expect(created).toEqual([]);
    expect(process.exitCode).toBe(1);
  });

  it('--non-fatal logs an ERROR with the count but exits 0 so a post-upgrade hook never blocks a release', async () => {
    const { cmd } = make({ __fail: [] });
    const error = vi
      .spyOn((cmd as any).logger, 'error')
      .mockImplementation(() => {});
    await cmd.run([], { nonFatal: true });
    expect(process.exitCode).toBe(0);
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining(
        'ERROR memberships:migrate-from-realms tenantsFailed=1',
      ),
    );
  });
});

describe('KeycloakAdminClient.listRealmRoleMemberIds', () => {
  const client = (impl: () => Promise<unknown>) => {
    const c = Object.create(KeycloakAdminClient.prototype);
    c.adminRequest = vi.fn(impl);
    return c as KeycloakAdminClient;
  };

  it('a role the realm does not have (404) means nobody holds it', async () => {
    const c = client(() =>
      Promise.reject(
        new Error('Keycloak Admin API GET /x failed with HTTP 404: not found'),
      ),
    );
    await expect(c.listRealmRoleMemberIds('r', 'AUDITOR')).resolves.toEqual([]);
  });

  it('any other failure is still an error', async () => {
    const c = client(() =>
      Promise.reject(
        new Error('Keycloak Admin API GET /x failed with HTTP 500'),
      ),
    );
    await expect(c.listRealmRoleMemberIds('r', 'AUDITOR')).rejects.toThrow(
      'HTTP 500',
    );
  });
});

describe('memberships:grant', () => {
  it('clears the API replicas auth cache after the roles are written, and waits for it', async () => {
    const order: string[] = [];
    const control = {
      tenant: {
        findUnique: vi.fn().mockResolvedValue({
          id: 't1',
          slug: 'acme',
          keycloakIssuerUrl: ISSUER,
        }),
      },
      membership: {
        upsert: vi.fn(() => {
          order.push('upsert');
          return Promise.resolve({});
        }),
      },
    };
    const cache = {
      invalidate: vi.fn(async () => {
        await Promise.resolve();
        order.push('invalidate');
      }),
    };
    const cmd = new MembershipsGrantCommand(control as never, cache as never);
    await cmd.run([], {
      tenant: 'acme',
      subject: 's1',
      roles: ['TENANT_OWNER'],
    });
    expect(order).toEqual(['upsert', 'invalidate']);
  });
});
