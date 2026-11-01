import { describe, expect, it, vi } from 'vitest';
import { ApproverDirectory } from './approver-directory';

function make(opts: {
  memberships: boolean;
  active: string[];
  bindings?: string[];
}) {
  const calls: string[] = [];
  const control = {
    $queryRaw: vi.fn((strings: TemplateStringsArray) => {
      const q = strings.join('?');
      calls.push(q);
      if (q.includes('to_regclass'))
        return Promise.resolve([
          { t: opts.memberships ? 'memberships' : null },
        ]);
      return Promise.resolve(opts.active.map((subject) => ({ subject })));
    }),
  };
  const tenantClient = {
    roleBinding: {
      findMany: () =>
        Promise.resolve(
          (opts.bindings ?? []).map((s) => ({ user: { keycloakSubject: s } })),
        ),
      findFirst: ({
        where,
      }: {
        where: { user: { keycloakSubject: string } };
      }) =>
        Promise.resolve(
          (opts.bindings ?? []).includes(where.user.keycloakSubject)
            ? { id: 'r' }
            : null,
        ),
    },
  };
  return {
    dir: new ApproverDirectory(control as never),
    tenantClient: tenantClient as never,
    calls,
  };
}

describe('ApproverDirectory', () => {
  it('uses current memberships, not stale role bindings, once memberships exist', async () => {
    const w = make({ memberships: true, active: ['alice'], bindings: ['bob'] });
    expect(await w.dir.canApprove('t1', w.tenantClient, 'alice')).toBe(true);
    // bob still has a synced binding but no active approver membership: removed approver.
    expect(await w.dir.canApprove('t1', w.tenantClient, 'bob')).toBe(false);
    expect(await w.dir.listSubjects('t1', w.tenantClient)).toEqual(['alice']);
  });

  it('falls back to role bindings only where there is no memberships table', async () => {
    const w = make({ memberships: false, active: [], bindings: ['bob'] });
    expect(await w.dir.canApprove('t1', w.tenantClient, 'bob')).toBe(true);
  });

  it('fails closed on a missing subject or a lookup error', async () => {
    const w = make({ memberships: true, active: ['alice'] });
    expect(await w.dir.canApprove('t1', w.tenantClient, null)).toBe(false);
    const broken = new ApproverDirectory({
      $queryRaw: () => Promise.reject(new Error('db')),
    } as never);
    expect(await broken.canApprove('t1', w.tenantClient, 'alice')).toBe(false);
  });
});
