import { describe, expect, it, vi } from 'vitest';
import { verifyPushAction } from '../phone/phone-token';
import { PushService, type PushSender } from './push.service';

type Sub = {
  id: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  tenantId: string;
  subject: string;
};

function setup(subs: Sub[], approverSubjects: string[], sender: PushSender) {
  const deleted: string[] = [];
  const control = {
    pushSubscription: {
      findMany: vi.fn(
        ({
          where,
        }: {
          where: { tenantId: string; subject: { in: string[] } };
        }) =>
          Promise.resolve(
            subs.filter(
              (s) =>
                s.tenantId === where.tenantId &&
                where.subject.in.includes(s.subject),
            ),
          ),
      ),
      deleteMany: vi.fn(({ where }: { where: { id?: string } }) => {
        if (where.id) deleted.push(where.id);
        return Promise.resolve({ count: 1 });
      }),
    },
  };
  const config = { get: () => 'x' };
  const service = new PushService(
    control as never,
    { listSubjects: () => Promise.resolve(approverSubjects) } as never,
    config as never,
    sender,
  );
  const tenantClient = {
    roleBinding: {
      findMany: () =>
        Promise.resolve(
          approverSubjects.map((s) => ({ user: { keycloakSubject: s } })),
        ),
    },
  };
  return { service, tenantClient: tenantClient as never, deleted };
}

const sub = (id: string, subject: string, tenantId = 't1'): Sub => ({
  id,
  endpoint: `https://fcm.googleapis.com/fcm/send/${id}`,
  p256dh: 'k',
  auth: 'a',
  tenantId,
  subject,
});
const payload = {
  kind: 'approval' as const,
  title: 'WARDEN',
  body: 'x',
  url: '/approvals',
  tag: 't',
};

describe('PushService', () => {
  it('sends only to subscribed approvers of this workspace', async () => {
    const sender = vi.fn<PushSender>().mockResolvedValue({});
    const { service, tenantClient } = setup(
      [
        sub('a', 'approver'),
        sub('b', 'developer'),
        sub('c', 'approver', 'other-tenant'),
      ],
      ['approver'],
      sender,
    );
    expect(await service.notifyApprovers(tenantClient, 't1', payload)).toBe(1);
    expect(sender).toHaveBeenCalledTimes(1);
    expect(sender.mock.calls[0]![0].endpoint).toBe(
      'https://fcm.googleapis.com/fcm/send/a',
    );
  });

  it('prunes subscriptions the push service reports gone (404, 410), keeps others', async () => {
    const sender = vi.fn<PushSender>(({ endpoint }) => {
      if (endpoint.endsWith('/a'))
        return Promise.reject(
          Object.assign(new Error('gone'), { statusCode: 410 }),
        );
      if (endpoint.endsWith('/b'))
        return Promise.reject(
          Object.assign(new Error('nf'), { statusCode: 404 }),
        );
      if (endpoint.endsWith('/c'))
        return Promise.reject(
          Object.assign(new Error('busy'), { statusCode: 503 }),
        );
      return Promise.resolve({});
    });
    const { service, tenantClient, deleted } = setup(
      [sub('a', 'u'), sub('b', 'u'), sub('c', 'u'), sub('d', 'u')],
      ['u'],
      sender,
    );
    expect(await service.notifyApprovers(tenantClient, 't1', payload)).toBe(1);
    expect(deleted.sort()).toEqual(['a', 'b']);
  });

  it('sends nothing and never throws when push is not configured', async () => {
    const control = {} as never;
    const service = new PushService(
      control,
      {} as never,
      { get: () => undefined } as never,
    );
    expect(service.enabled).toBe(false);
    expect(await service.notifyApprovers({} as never, 't1', payload)).toBe(0);
  });

  it('never contacts a stored endpoint outside the push services, and deletes the row', async () => {
    const sender = vi.fn<PushSender>().mockResolvedValue({});
    const bad: Sub = {
      ...sub('x', 'u'),
      endpoint: 'http://169.254.169.254/latest',
    };
    const { service, tenantClient, deleted } = setup(
      [bad, sub('ok', 'u')],
      ['u'],
      sender,
    );
    expect(await service.notifyApprovers(tenantClient, 't1', payload)).toBe(1);
    expect(sender).toHaveBeenCalledTimes(1);
    expect(deleted).toContain('x');
  });

  it('refuses to subscribe an endpoint that is not a push service', async () => {
    const { service } = setup([], [], vi.fn<PushSender>());
    await expect(
      service.subscribe('u', 't1', {
        endpoint: 'https://127.0.0.1/x',
        p256dh: 'k',
        auth: 'a',
      }),
    ).rejects.toThrow('not a browser push service');
  });

  it('gives each subscriber its own signed token for an actionable approval, and none otherwise', async () => {
    const sender = vi.fn<PushSender>().mockResolvedValue({});
    const { service, tenantClient } = setup(
      [sub('a', 'u1'), sub('b', 'u2')],
      ['u1', 'u2'],
      sender,
    );
    const id = '3f2b1c9e-8d7a-4b6c-9e5d-1a2b3c4d5e6f';
    const e = Date.now() + 60_000;
    await service.notifyApprovers(tenantClient, 't1', {
      ...payload,
      approvalId: id,
      actionable: true,
      expiresAt: e,
    });
    const bodies = sender.mock.calls.map(
      (c) => JSON.parse(c[1]) as { action?: string; actionable?: boolean },
    );
    const claims = bodies.map((b) => verifyPushAction('x', b.action!));
    expect(claims.map((c) => c?.s).sort()).toEqual(['u1', 'u2']);
    expect(claims.every((c) => c?.a === id && c.t === 't1')).toBe(true);
    expect(bodies[0]!.actionable).toBeUndefined();
    sender.mockClear();
    await service.notifyApprovers(tenantClient, 't1', {
      ...payload,
      approvalId: id,
    });
    expect(
      (JSON.parse(sender.mock.calls[0]![1]) as { action?: string }).action,
    ).toBeUndefined();
  });
});
