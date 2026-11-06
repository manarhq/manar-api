import { UsersService } from './users.service';
import { LastOwnerError, PrivilegeEscalationError } from './users.errors';

function make(
  initial: { role: string; extraRoles: string[]; status: string } | null,
  /** Other ACTIVE owners of the workspace (the owner query returns them with the target). */
  otherOwners: { issuer: string; subject: string }[] = [],
) {
  let m = initial && {
    subject: 'sub-t',
    createdAt: new Date(),
    updatedAt: new Date(),
    grantedBy: null,
    ...initial,
  };
  const self: { control: object } = { control: {} };
  const control = {
    $transaction: vi.fn((fn: (tx: object) => unknown) => fn(self.control)),
    $executeRaw: vi.fn(() => Promise.resolve(1)),
    membership: {
      findMany: vi.fn(() => Promise.resolve(m ? [m] : [])),
      // the other-owners count (the target itself is excluded by the query)
      count: vi.fn(() => Promise.resolve(otherOwners.length)),
      upsert: vi.fn(({ create, update }: any) => {
        m = {
          ...(m ?? { createdAt: new Date() }),
          ...(m ? update : create),
          updatedAt: new Date(),
        } as never;
        return Promise.resolve(m);
      }),
      update: vi.fn(({ data }: any) => {
        m = { ...m, ...data } as never;
        return Promise.resolve(m);
      }),
    },
  };
  const client = {
    userProfile: {
      findUnique: () =>
        Promise.resolve({
          id: 'u1',
          keycloakSubject: 'sub-t',
          email: 'e',
          displayName: 'T',
          createdAt: new Date(),
          lastSeenAt: new Date(),
        }),
    },
  };
  self.control = control;
  const audit = { recordSafely: vi.fn() };
  return {
    svc: new UsersService(audit as never, control as never),
    client: client as never,
    control,
    audit,
  };
}
const base = {
  tenantId: 't1',
  issuer: 'https://kc.test/realms/manar',
  targetUserId: 'u1',
  grantedByUserId: 'a',
  grantedByRoles: ['SECURITY_ADMIN'] as never,
  revokedByUserId: 'a',
  revokedByRoles: ['SECURITY_ADMIN'] as never,
};

describe('UsersService roles live in Membership', () => {
  it('grant adds a role to the Membership, no Keycloak involved', async () => {
    const { svc, client, control } = make({
      role: 'AUDITOR',
      extraRoles: [],
      status: 'ACTIVE',
    });
    const r = await svc.grantRole(client, { ...base, role: 'SOC_OPERATOR' });
    expect(r.roles.map((x) => x.role)).toEqual(['SOC_OPERATOR', 'AUDITOR']);
    expect(control.membership.upsert).toHaveBeenCalled();
  });

  it('refuses a grant above the caller, before any write', async () => {
    const { svc, client, control } = make(null);
    await expect(
      svc.grantRole(client, { ...base, role: 'TENANT_OWNER' }),
    ).rejects.toThrow(PrivilegeEscalationError);
    expect(control.membership.upsert).not.toHaveBeenCalled();
  });

  it('revoking the last role removes the member, who then holds no roles', async () => {
    const { svc, client } = make({
      role: 'AUDITOR',
      extraRoles: [],
      status: 'ACTIVE',
    });
    const r = await svc.revokeRole(client, { ...base, role: 'AUDITOR' });
    expect(r.roles).toEqual([]);
  });

  it('a PENDING member shows no roles', async () => {
    const { svc, client } = make({
      role: 'DEVELOPER',
      extraRoles: [],
      status: 'PENDING',
    });
    expect(
      (await svc.getUserOrThrow(client, 't1', base.issuer, 'u1')).roles,
    ).toEqual([]);
  });

  it('the only owner cannot lose TENANT_OWNER, themselves or by another admin: last_owner, nothing written', async () => {
    const { svc, client, control, audit } = make({
      role: 'TENANT_OWNER',
      extraRoles: [],
      status: 'ACTIVE',
    });
    await expect(
      svc.revokeRole(client, {
        ...base,
        role: 'TENANT_OWNER',
        revokedByRoles: ['TENANT_OWNER'] as never,
      }),
    ).rejects.toThrow(LastOwnerError);
    expect(control.membership.update).not.toHaveBeenCalled();
    // the refusal is a security event of its own
    expect(audit.recordSafely).toHaveBeenCalledWith(
      client,
      't1',
      expect.objectContaining({
        eventType: 'user.role_revoke_refused',
        data: {
          targetUserId: 'u1',
          role: 'TENANT_OWNER',
          reason: 'last_owner',
        },
      }),
    );
  });

  it('a revoke above the caller is 403 before any owner check or lock', async () => {
    const { svc, client, control } = make({
      role: 'TENANT_OWNER',
      extraRoles: [],
      status: 'ACTIVE',
    });
    await expect(
      svc.revokeRole(client, { ...base, role: 'TENANT_OWNER' }), // caller is only SECURITY_ADMIN
    ).rejects.toThrow(PrivilegeEscalationError);
    expect(control.$transaction).not.toHaveBeenCalled();
  });

  it('the same holds when TENANT_OWNER is an extra role of the only owner', async () => {
    const { svc, client, control } = make({
      role: 'SECURITY_ADMIN',
      extraRoles: ['TENANT_OWNER'],
      status: 'ACTIVE',
    });
    await expect(
      svc.revokeRole(client, {
        ...base,
        role: 'TENANT_OWNER',
        revokedByRoles: ['TENANT_OWNER'] as never,
      }),
    ).rejects.toThrow(LastOwnerError);
    expect(control.membership.update).not.toHaveBeenCalled();
  });

  it('an owner can be revoked while another active owner remains, under the per-workspace lock', async () => {
    const { svc, client, control } = make(
      { role: 'TENANT_OWNER', extraRoles: [], status: 'ACTIVE' },
      [{ issuer: base.issuer, subject: 'sub-other' }],
    );
    const r = await svc.revokeRole(client, {
      ...base,
      role: 'TENANT_OWNER',
      revokedByRoles: ['TENANT_OWNER'] as never,
    });
    expect(r.roles).toEqual([]);
    expect(control.$executeRaw).toHaveBeenCalledTimes(1);
  });

  it('revoking a role that is not TENANT_OWNER never needs the owner check', async () => {
    const { svc, client, control } = make({
      role: 'AUDITOR',
      extraRoles: [],
      status: 'ACTIVE',
    });
    await svc.revokeRole(client, { ...base, role: 'AUDITOR' });
    expect(control.$transaction).not.toHaveBeenCalled();
  });
});
