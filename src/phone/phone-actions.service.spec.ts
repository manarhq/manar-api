import { describe, expect, it, vi } from 'vitest';
import { PhoneActionsService } from './phone-actions.service';
import { signPushAction } from './phone-token';

const SECRET = 'unit-test-signing-secret-0123456789';
const ID = '3f2b1c9e-8d7a-4b6c-9e5d-1a2b3c4d5e6f';

function setup(opts: { approver?: boolean; highRisk?: boolean } = {}) {
  const used = new Set<string>();
  const control = {
    phoneActionUse: {
      create: vi.fn(({ data }: { data: { nonce: string } }) => {
        if (used.has(data.nonce)) return Promise.reject(new Error('unique'));
        used.add(data.nonce);
        return Promise.resolve({});
      }),
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
    },
  };
  const decide = vi.fn().mockResolvedValue({
    id: ID,
    status: 'APPROVED',
    decision: 'approve_once',
  });
  const svc = new PhoneActionsService(
    control as never,
    { getClient: () => Promise.resolve({}) } as never,
    { canApprove: () => Promise.resolve(opts.approver ?? true) } as never,
    {
      get: () => Promise.resolve({ highRisk: opts.highRisk ?? false }),
      decide,
    } as never,
    { get: () => SECRET } as never,
  );
  const auth = (subject = 'u1', tenant = 't1') =>
    ({ tenant: { id: tenant }, user: { keycloakSubject: subject } }) as never;
  const token = (s = 'u1', t = 't1', e = Date.now() + 60_000) =>
    signPushAction(SECRET, { a: ID, s, t, e }).token;
  return { svc, decide, auth, token };
}

describe('PhoneActionsService.decideFromPush', () => {
  it('decides once for the right person and workspace, via push', async () => {
    const { svc, decide, auth, token } = setup();
    const tk = token();
    await svc.decideFromPush(auth(), tk, 'approve_once');
    expect(decide).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({
        approvalId: ID,
        subject: 'u1',
        via: 'push',
        decision: 'approve_once',
      }),
    );
    // The same token again, with either button, is refused.
    await expect(svc.decideFromPush(auth(), tk, 'deny')).rejects.toThrow(
      'action_already_used',
    );
    expect(decide).toHaveBeenCalledTimes(1);
  });

  it('refuses a token that belongs to another person, workspace or is expired', async () => {
    const { svc, decide, auth, token } = setup();
    await expect(
      svc.decideFromPush(auth('u2'), token(), 'deny'),
    ).rejects.toThrow('invalid_action');
    await expect(
      svc.decideFromPush(auth('u1', 't2'), token(), 'deny'),
    ).rejects.toThrow('invalid_action');
    await expect(
      svc.decideFromPush(auth(), token('u1', 't1', Date.now() - 1), 'deny'),
    ).rejects.toThrow('invalid_action');
    await expect(
      svc.decideFromPush(auth(), 'junk.token', 'deny'),
    ).rejects.toThrow('invalid_action');
    expect(decide).not.toHaveBeenCalled();
  });

  it('refuses when the person is no longer an approver, and for high-risk approvals', async () => {
    const a = setup({ approver: false });
    await expect(
      a.svc.decideFromPush(a.auth(), a.token(), 'approve_once'),
    ).rejects.toThrow('not_an_approver');
    const b = setup({ highRisk: true });
    await expect(
      b.svc.decideFromPush(b.auth(), b.token(), 'approve_once'),
    ).rejects.toThrow('high_risk_open_in_console');
    expect(a.decide).not.toHaveBeenCalled();
    expect(b.decide).not.toHaveBeenCalled();
  });
});
