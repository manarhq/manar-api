/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { MembersService } from './members.service';
import { signToken } from './signed-token';

const SECRET = 's'.repeat(32);
const MS_TENANT = '11111111-2222-3333-4444-555555555555';
const identity = (over: Record<string, unknown> = {}) =>
  ({
    issuer: 'iss',
    subject: 'u1',
    email: 'a@corp.com',
    wids: [],
    idp: 'microsoft',
    tid: MS_TENANT,
    ...over,
  }) as never;

function setup(
  over: {
    verified?: string | null;
    members?: number;
    tenant?: object | null;
    plan?: string;
    status?: string;
    membership?: object | null;
  } = {},
) {
  const memberships = { create: vi.fn(), update: vi.fn() };
  const invites = new Map<
    string,
    {
      id: string;
      tenantId: string;
      email: string;
      role: string;
      usedAt: Date | null;
      revokedAt: Date | null;
      expiresAt: Date;
      createdBy: string;
    }
  >();
  const control = {
    tenant: {
      findUnique: async () =>
        over.tenant === undefined
          ? {
              id: 't',
              kind: 'COMPANY',
              status: 'ACTIVE',
              name: 'Co',
              entraTenantId: MS_TENANT,
            }
          : over.tenant,
      findFirst: async () =>
        over.tenant === undefined
          ? {
              id: 't',
              kind: 'COMPANY',
              status: 'ACTIVE',
              entraTenantId: MS_TENANT,
              autoJoinEntra: true,
            }
          : over.tenant,
    },
    membership: {
      findUnique: async () => over.membership ?? null,
      count: async () => over.members ?? 3,
      ...memberships,
    },
    workspaceInvite: {
      findUnique: async ({ where }: { where: { id: string } }) =>
        invites.get(where.id) ?? null,
      updateMany: async ({ where }: { where: { id: string } }) => {
        const i = invites.get(where.id);
        if (!i || i.usedAt || i.revokedAt) return { count: 0 };
        i.usedAt = new Date();
        return { count: 1 };
      },
    },
  };
  const authCache = { invalidate: vi.fn() };
  const svc = new MembersService(
    control as never,
    {
      get: async () => ({
        plan: over.plan ?? 'company_trial',
        status: over.status ?? 'active',
      }),
    } as never,
    { send: async () => true } as never,
    { record: vi.fn() } as never,
    { verified: async () => over.verified ?? null } as never,
    {
      get: (k: string) => (k === 'MANAR_LINK_SECRET' ? SECRET : undefined),
    } as never,
    authCache as never,
  );
  return { svc, memberships, invites, authCache };
}

describe('Microsoft auto-join', () => {
  it('joins on the verified tid of a Microsoft sign-in', async () => {
    const { svc, memberships, authCache } = setup();
    expect((await svc.autoJoin(identity())).tenantId).toBe('t');
    expect(memberships.create).toHaveBeenCalledOnce();
    expect(authCache.invalidate).toHaveBeenCalledOnce();
  });
  it('never matches on email domain, other sign-in methods or the consumer tenant', async () => {
    for (const over of [
      { idp: 'github' },
      { tid: undefined },
      { tid: '9188040d-6c67-4c5b-b112-36a304b66dad' },
    ]) {
      const { svc, memberships } = setup();
      expect((await svc.autoJoin(identity(over))).tenantId).toBeNull();
      expect(memberships.create).not.toHaveBeenCalled();
    }
  });
  it('only offers a prompt; joining needs the explicit call', async () => {
    const { svc, memberships } = setup();
    expect((await svc.autoJoinOffer(identity())).offer).toMatchObject({
      tenantId: 't',
    });
    expect(memberships.create).not.toHaveBeenCalled();
    expect(
      (
        await setup({ membership: { status: 'REMOVED' } }).svc.autoJoinOffer(
          identity(),
        )
      ).offer,
    ).toBeNull();
  });
  it('stops at the seat cap', async () => {
    const full = setup({ members: 25 });
    expect((await full.svc.autoJoinOffer(identity())).offer).toBeNull();
    await expect(full.svc.autoJoin(identity())).rejects.toThrow(
      'seat_cap_reached',
    );
    expect(full.memberships.create).not.toHaveBeenCalled();
  });
  it('does nothing when off, for a lapsed workspace, or for someone removed', async () => {
    expect(
      (await setup({ tenant: null }).svc.autoJoin(identity())).tenantId,
    ).toBeNull();
    expect(
      (await setup({ status: 'read_only' }).svc.autoJoin(identity())).tenantId,
    ).toBeNull();
    const removed = setup({ membership: { status: 'REMOVED' } });
    expect((await removed.svc.autoJoin(identity())).tenantId).toBeNull();
    expect(removed.memberships.create).not.toHaveBeenCalled();
  });
});

describe('invites', () => {
  const seed = (s: ReturnType<typeof setup>) => {
    const row = {
      id: 'i1',
      tenantId: 't',
      email: 'a@corp.com',
      role: 'DEVELOPER',
      usedAt: null,
      revokedAt: null,
      expiresAt: new Date(Date.now() + 1e6),
      createdBy: 'admin',
    };
    s.invites.set('i1', row);
    return signToken(SECRET, 'invite', 'i1', row.expiresAt);
  };
  it('needs the invited address as a VERIFIED contact email, not the token email', async () => {
    const s = setup(); // no verified contact email
    const token = seed(s);
    // the token says a@corp.com, but a Microsoft/GitHub token email is not proof
    await expect(s.svc.acceptInvite(identity(), token)).rejects.toThrow(
      'invite_email_mismatch',
    );
    const other = setup({ verified: 'evil@x.com' });
    const t2 = seed(other);
    await expect(other.svc.acceptInvite(identity(), t2)).rejects.toThrow(
      'invite_email_mismatch',
    );
    expect(s.memberships.create).not.toHaveBeenCalled();
  });
  it('accepts an email-link sign-in to the invited address', async () => {
    const s = setup();
    const token = seed(s);
    await s.svc.acceptInvite(
      identity({ idp: undefined, tid: undefined }),
      token,
    );
    expect(s.memberships.create).toHaveBeenCalledOnce();
    expect(s.authCache.invalidate).toHaveBeenCalledOnce(); // invite accept
  });
  it('refuses to invite a placeholder address', async () => {
    const s = setup();
    await expect(
      s.svc.createInvite('t', 'admin', 'abc@idp.invalid', 'DEVELOPER'),
    ).rejects.toThrow('invite_email_invalid');
  });
  it('is single use', async () => {
    const s = setup({ verified: 'a@corp.com' });
    const token = seed(s);
    await s.svc.acceptInvite(identity(), token);
    expect(s.memberships.create).toHaveBeenCalledOnce();
    await expect(s.svc.acceptInvite(identity(), token)).rejects.toThrow(
      'invite_unavailable',
    );
  });
  it('refuses a forged token and a lapsed workspace', async () => {
    const s = setup();
    seed(s);
    await expect(s.svc.acceptInvite(identity(), 'x.y')).rejects.toThrow(
      'invite_invalid',
    );
    const lapsed = setup({ status: 'read_only', verified: 'a@corp.com' });
    const t = seed(lapsed);
    await expect(lapsed.svc.acceptInvite(identity(), t)).rejects.toThrow(
      'workspace_read_only',
    );
  });
});
