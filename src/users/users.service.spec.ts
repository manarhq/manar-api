import { UsersService } from './users.service';
import { PrivilegeEscalationError } from './users.errors';

function make(
  initial: { role: string; extraRoles: string[]; status: string } | null,
) {
  let m = initial && {
    subject: 'sub-t',
    createdAt: new Date(),
    updatedAt: new Date(),
    grantedBy: null,
    ...initial,
  };
  const control = {
    membership: {
      findMany: vi.fn(() => Promise.resolve(m ? [m] : [])),
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
  const audit = { recordSafely: vi.fn() };
  return {
    svc: new UsersService(audit as never, control as never),
    client: client as never,
    control,
  };
}
const base = {
  tenantId: 't1',
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
    expect((await svc.getUserOrThrow(client, 't1', 'u1')).roles).toEqual([]);
  });
});
