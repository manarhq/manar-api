/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call -- in-memory fakes of the control DB */
import {
  ForbiddenException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { RequestWithAuthContext } from './auth-context';
import { JwtAuthGuard } from './jwt-auth.guard';
import { MembershipService } from './membership.service';
import type {
  TokenVerifierService,
  VerifiedIdentity,
} from './token-verifier.service';

/**
 * Tenant isolation at the guard: tenant and roles come from Membership only.
 * The token verifier is faked (its own spec covers token checks); the Membership
 * service is the real one over an in-memory control DB fake that applies the same
 * `where` filters Prisma would.
 */
type M = {
  id: string;
  subject: string;
  tenantId: string;
  role: string;
  extraRoles: string[];
  status: 'ACTIVE' | 'PENDING' | 'REMOVED';
  createdAt: Date;
  tenant: { id: string; slug: string; kind: string; status: string };
};
const T = (id: string, kind = 'COMPANY', status = 'ACTIVE') => ({
  id,
  slug: id,
  kind,
  status,
});
const mem = (
  subject: string,
  tenant: M['tenant'],
  role: string,
  extra: string[] = [],
  status: M['status'] = 'ACTIVE',
  n = 0,
): M => ({
  id: `m-${subject}-${tenant.id}`,
  subject,
  tenantId: tenant.id,
  role,
  extraRoles: extra,
  status,
  createdAt: new Date(n),
  tenant,
});

function setup(
  rows: M[],
  identity: Partial<VerifiedIdentity> & { subject: string },
) {
  const control = {
    membership: {
      findMany: ({ where }: { where: any }) =>
        Promise.resolve(
          rows
            .filter((r) => r.subject === where.subject)
            .filter(
              (r) =>
                !where.status ||
                (typeof where.status === 'string'
                  ? r.status === where.status
                  : where.status.in.includes(r.status)),
            )
            .filter((r) => !where.tenantId || r.tenantId === where.tenantId)
            .filter(
              (r) => !where.tenant || r.tenant.status === where.tenant.status,
            ),
        ),
    },
  } as unknown as ControlPrismaService;
  const upsert = vi.fn().mockResolvedValue({
    id: 'u1',
    keycloakSubject: identity.subject,
    email: '',
    displayName: 'x',
  });
  const getClient = vi.fn().mockResolvedValue({ userProfile: { upsert } });
  const guard = new JwtAuthGuard(
    {
      verify: () => Promise.resolve({ wids: [], issuer: 'i', ...identity }),
    } as unknown as TokenVerifierService,
    new MembershipService(control),
    { getClient } as unknown as TenantDatabaseManager,
  );
  const run = async (headers: Record<string, string> = {}) => {
    const request = {
      headers: { authorization: 'Bearer t', ...headers },
    } as unknown as RequestWithAuthContext;
    const context = {
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
    await guard.canActivate(context);
    return request;
  };
  return { run, getClient };
}

describe('JwtAuthGuard: tenant and roles come from Membership', () => {
  it('uses the personal workspace by default and the Membership roles', async () => {
    const { run } = setup(
      [
        mem('s1', T('co'), 'AUDITOR', [], 'ACTIVE', 0),
        mem(
          's1',
          T('me', 'PERSONAL'),
          'TENANT_OWNER',
          ['AUDITOR'],
          'ACTIVE',
          1,
        ),
      ],
      { subject: 's1' },
    );
    const req = await run();
    expect(req.authContext?.tenant.id).toBe('me');
    expect(req.authContext?.workspaceKind).toBe('PERSONAL');
    expect(req.authContext?.roles).toEqual(['TENANT_OWNER', 'AUDITOR']);
  });

  it('switches to the selected workspace when the user is a member', async () => {
    const { run } = setup(
      [
        mem('s1', T('co'), 'READ_ONLY'),
        mem('s1', T('me', 'PERSONAL'), 'TENANT_OWNER'),
      ],
      { subject: 's1' },
    );
    const req = await run({ 'x-manar-workspace': 'co' });
    expect(req.authContext?.tenant.id).toBe('co');
    expect(req.authContext?.roles).toEqual(['READ_ONLY']);
  });

  it('403 when the user has no Membership for the selected tenant, and never opens its database', async () => {
    const { run, getClient } = setup(
      [
        mem('s1', T('me', 'PERSONAL'), 'TENANT_OWNER'),
        mem('other', T('victim'), 'TENANT_OWNER'),
      ],
      { subject: 's1' },
    );
    await expect(run({ 'x-manar-workspace': 'victim' })).rejects.toThrow(
      ForbiddenException,
    );
    expect(getClient).not.toHaveBeenCalled();
  });

  it.each(['PENDING', 'REMOVED'] as const)(
    '403 for a %s Membership',
    async (status) => {
      const { run } = setup([mem('s1', T('co'), 'TENANT_OWNER', [], status)], {
        subject: 's1',
      });
      await expect(run({ 'x-manar-workspace': 'co' })).rejects.toThrow(
        ForbiddenException,
      );
    },
  );

  it('403 for a suspended tenant even with an ACTIVE Membership', async () => {
    const { run } = setup(
      [mem('s1', T('co', 'COMPANY', 'SUSPENDED'), 'TENANT_OWNER')],
      { subject: 's1' },
    );
    await expect(run({ 'x-manar-workspace': 'co' })).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('403 for a signed-in user with no workspace at all', async () => {
    const { run } = setup([], { subject: 'new' });
    await expect(run()).rejects.toThrow(ForbiddenException);
  });

  it('a legacy per-tenant realm token only reaches its own tenant', async () => {
    const rows = [
      mem('s1', T('legacy'), 'SOC_OPERATOR'),
      mem('s1', T('me', 'PERSONAL'), 'TENANT_OWNER'),
    ];
    const { run } = setup(rows, {
      subject: 's1',
      boundTenant: { id: 'legacy', slug: 'legacy' },
    });
    expect((await run()).authContext?.tenant.id).toBe('legacy');
    await expect(run({ 'x-manar-workspace': 'me' })).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('ignores roles in the token: the verified identity has none and the Membership decides', async () => {
    // The verifier fake even smuggles a roles-like field; the guard must not read it.
    const { run } = setup([mem('s1', T('co'), 'READ_ONLY')], {
      subject: 's1',
      ...({
        roles: ['TENANT_OWNER'],
        realm_access: { roles: ['TENANT_OWNER'] },
      } as object),
    });
    expect((await run()).authContext?.roles).toEqual(['READ_ONLY']);
  });

  it('a missing bearer token is a 401', async () => {
    const { run } = setup([], { subject: 's1' });
    const guard = new JwtAuthGuard(
      {} as TokenVerifierService,
      {} as MembershipService,
      {} as TenantDatabaseManager,
    );
    const context = {
      switchToHttp: () => ({ getRequest: () => ({ headers: {} }) }),
    } as unknown as ExecutionContext;
    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
    void run;
  });
});

describe('SAMPLE workspaces are never a default', () => {
  it('without a selection a SAMPLE membership is not picked', async () => {
    const { run } = setup([mem('s1', T('sample', 'SAMPLE'), 'TENANT_OWNER')], {
      subject: 's1',
    });
    await expect(run()).rejects.toThrow(ForbiddenException);
    expect(
      (await run({ 'x-manar-workspace': 'sample' })).authContext?.workspaceKind,
    ).toBe('SAMPLE');
  });
});
