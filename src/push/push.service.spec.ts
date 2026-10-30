import { describe, expect, it, vi } from 'vitest';
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
  const service = new PushService(control as never, config as never, sender);
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
  endpoint: `https://push.example/${id}`,
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
    expect(sender.mock.calls[0]![0].endpoint).toBe('https://push.example/a');
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
    const service = new PushService(control, { get: () => undefined } as never);
    expect(service.enabled).toBe(false);
    expect(await service.notifyApprovers({} as never, 't1', payload)).toBe(0);
  });
});
