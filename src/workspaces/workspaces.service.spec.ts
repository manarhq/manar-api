/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-argument, @typescript-eslint/require-await -- in-memory fakes of the control DB */
import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { VerifiedIdentity } from '../auth/token-verifier.service';
import type { WorkspaceProvisioningService } from './workspace-provisioning.service';
import {
  CONSUMER_TENANT_ID,
  GLOBAL_ADMIN_WID,
  WorkspacesService,
} from './workspaces.service';

const id = (
  o: Partial<VerifiedIdentity> & { subject: string },
): VerifiedIdentity => ({
  issuer: 'i',
  wids: [],
  ...o,
});

/** A small in-memory control DB: tenants and memberships with just the filters the service uses. */
function world() {
  const tenants: any[] = [];
  const memberships: any[] = [];
  let n = 0;
  const control = {
    tenant: {
      findFirst: ({ where }: any) =>
        Promise.resolve(
          tenants.find(
            (t) =>
              (!where.kind || t.kind === where.kind) &&
              (!where.ownerSubject || t.ownerSubject === where.ownerSubject) &&
              (!where.entraTenantId || t.entraTenantId === where.entraTenantId),
          ) ?? null,
        ),
    },
    membership: {
      findUnique: ({ where }: any) =>
        Promise.resolve(
          memberships.find(
            (m) =>
              m.subject === where.subject_tenantId.subject &&
              m.tenantId === where.subject_tenantId.tenantId,
          ) ?? null,
        ),
      create: ({ data }: any) => {
        const m = { id: `m${++n}`, createdAt: new Date(), ...data };
        memberships.push(m);
        return Promise.resolve(m);
      },
      update: ({ where, data }: any) => {
        const m = memberships.find((x) => x.id === where.id);
        Object.assign(m, data);
        return Promise.resolve(m);
      },
      findMany: ({ where }: any) =>
        Promise.resolve(
          memberships
            .filter(
              (m) =>
                m.subject === where.subject &&
                where.status.in.includes(m.status),
            )
            .map((m) => ({
              ...m,
              tenant: tenants.find((t) => t.id === m.tenantId),
            })),
        ),
      findFirst: ({ where }: any) =>
        Promise.resolve(
          memberships.find(
            (m) =>
              m.id === where.id &&
              m.tenantId === where.tenantId &&
              m.status === where.status,
          ) ?? null,
        ),
    },
  };
  const createWorkspace = vi.fn(async (input: any) => {
    const tenant = {
      id: `t${tenants.length + 1}`,
      name: input.displayName,
      kind: input.kind,
      status: 'ACTIVE',
      ownerSubject: input.kind === 'PERSONAL' ? input.ownerSubject : null,
      entraTenantId: input.entraTenantId ?? null,
    };
    tenants.push(tenant);
    memberships.push({
      id: `mo${tenants.length}`,
      subject: input.ownerSubject,
      tenantId: tenant.id,
      status: 'ACTIVE',
      role: 'TENANT_OWNER',
      extraRoles: [],
    });
    return { tenantId: tenant.id, status: 'ACTIVE' as const };
  });
  const svc = new WorkspacesService(
    control as unknown as ControlPrismaService,
    { createWorkspace } as unknown as WorkspaceProvisioningService,
    {
      get: (k: string) =>
        k === 'COMPANY_TRIAL_ENABLED' ? undefined : undefined,
    } as never,
  );
  return { svc, tenants, memberships, createWorkspace };
}

describe('personal workspaces are keyed by subject, never by email', () => {
  it('a Microsoft user and a GitHub/magic-link user with the same email get separate workspaces', async () => {
    const { svc, tenants } = world();
    const ms = await svc.ensurePersonal(
      id({ subject: 'sub-microsoft', email: 'same@example.test', tid: 'T1' }),
    );
    const gh = await svc.ensurePersonal(
      id({ subject: 'sub-github', email: 'same@example.test' }),
    );
    const ml = await svc.ensurePersonal(
      id({ subject: 'sub-magic', email: 'SAME@example.test' }),
    );
    expect(new Set([ms.tenantId, gh.tenantId, ml.tenantId]).size).toBe(3);
    expect(tenants.map((t) => t.ownerSubject).sort()).toEqual([
      'sub-github',
      'sub-magic',
      'sub-microsoft',
    ]);
  });

  it('first sign-in is idempotent', async () => {
    const { svc, createWorkspace } = world();
    const a = await svc.ensurePersonal(id({ subject: 's1' }));
    const b = await svc.ensurePersonal(id({ subject: 's1' }));
    expect(b.tenantId).toBe(a.tenantId);
    expect(createWorkspace).toHaveBeenCalledTimes(1);
  });
});

describe('company workspaces (spec 7a)', () => {
  const admin = id({
    subject: 'admin',
    tid: 'tid-acme',
    wids: [GLOBAL_ADMIN_WID],
  });

  it('only an Entra admin with a work account can start a trial', async () => {
    const { svc } = world();
    await expect(
      svc.startCompanyTrial(id({ subject: 'u', tid: 'tid-acme' }), 'Acme'),
    ).rejects.toThrow('entra_admin_required');
    await expect(
      svc.startCompanyTrial(
        id({ subject: 'u', tid: CONSUMER_TENANT_ID, wids: [GLOBAL_ADMIN_WID] }),
        'Acme',
      ),
    ).rejects.toThrow('work_account_required');
    await expect(
      svc.startCompanyTrial(
        id({ subject: 'u', wids: [GLOBAL_ADMIN_WID] }),
        'Acme',
      ),
    ).rejects.toThrow(ForbiddenException);
    await expect(svc.startCompanyTrial(admin, 'Acme')).resolves.toMatchObject({
      status: 'ACTIVE',
    });
  });

  it('a matching tid never joins automatically: it only creates a PENDING request with no effective roles', async () => {
    const { svc, memberships } = world();
    const { tenantId } = await svc.startCompanyTrial(admin, 'Acme');
    const colleague = id({
      subject: 'colleague',
      tid: 'tid-acme',
      email: 'c@acme.test',
    });

    // Discovery and ensurePersonal must not create any membership in the company.
    await svc.companyForMe(colleague);
    await svc.ensurePersonal(colleague);
    expect(
      memberships.find(
        (m) => m.subject === 'colleague' && m.tenantId === tenantId,
      ),
    ).toBeUndefined();

    await expect(svc.requestToJoin(colleague)).resolves.toMatchObject({
      membershipStatus: 'PENDING',
    });
    const m = memberships.find(
      (x) => x.subject === 'colleague' && x.tenantId === tenantId,
    );
    expect(m.status).toBe('PENDING');
    // Listed workspaces show it as pending with no roles.
    const company = (await svc.list('colleague')).find(
      (w) => w.tenantId === tenantId,
    );
    expect(company).toMatchObject({ membershipStatus: 'PENDING', roles: [] });
  });

  it('a different Entra tenant cannot request to join, and cannot see the workspace', async () => {
    const { svc } = world();
    await svc.startCompanyTrial(admin, 'Acme');
    await expect(
      svc.requestToJoin(id({ subject: 'x', tid: 'tid-other' })),
    ).rejects.toThrow(NotFoundException);
    await expect(
      svc.companyForMe(id({ subject: 'x', tid: 'tid-other' })),
    ).resolves.toMatchObject({ company: null });
  });

  it('a consumer Microsoft account or a GitHub user cannot request to join', async () => {
    const { svc } = world();
    await svc.startCompanyTrial(admin, 'Acme');
    await expect(
      svc.requestToJoin(id({ subject: 'x', tid: CONSUMER_TENANT_ID })),
    ).rejects.toThrow(ForbiddenException);
    await expect(svc.requestToJoin(id({ subject: 'gh' }))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('only an admin decision activates a request, with Member (DEVELOPER) by default', async () => {
    const { svc, memberships } = world();
    const { tenantId } = await svc.startCompanyTrial(admin, 'Acme');
    await svc.requestToJoin(id({ subject: 'colleague', tid: 'tid-acme' }));
    const pending = memberships.find((m) => m.subject === 'colleague');
    await svc.decideJoinRequest(tenantId, pending.id, 'approve', 'admin');
    expect(pending).toMatchObject({ status: 'ACTIVE', role: 'DEVELOPER' });
  });

  it("an admin of one company cannot decide another company's request", async () => {
    const { svc, memberships } = world();
    await svc.startCompanyTrial(admin, 'Acme');
    const other = await svc.startCompanyTrial(
      id({ subject: 'admin2', tid: 'tid-b', wids: [GLOBAL_ADMIN_WID] }),
      'B',
    );
    await svc.requestToJoin(id({ subject: 'colleague', tid: 'tid-acme' }));
    const pending = memberships.find((m) => m.subject === 'colleague');
    await expect(
      svc.decideJoinRequest(other.tenantId, pending.id, 'approve', 'admin2'),
    ).rejects.toThrow(NotFoundException);
    expect(pending.status).toBe('PENDING');
  });

  it('already a member is a 409', async () => {
    const { svc } = world();
    await svc.startCompanyTrial(admin, 'Acme');
    await expect(svc.requestToJoin(admin)).rejects.toThrow(ConflictException);
  });
});
