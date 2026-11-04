import { staffAuditHash, staffCheckpointHash } from './staff-audit.service';

describe('staff audit hashes', () => {
  const row = {
    seq: '1',
    id: 'e1',
    at: '2026-11-04T10:00:00.000Z',
    staffId: 's1',
    action: 'person.viewed',
    targetType: 'ACCOUNT',
    targetId: 'a1',
    data: { b: 2, a: 1 },
    ip: '203.0.113.7',
    requestId: 'r1',
    previousHash: null,
  };

  it('row hash is stable for key order and covers every stored column', () => {
    const h = staffAuditHash(row);
    expect(staffAuditHash({ ...row, data: { a: 1, b: 2 } })).toBe(h);
    for (const [k, v] of Object.entries({
      seq: '2',
      id: 'e2',
      at: '2026-11-04T10:00:01.000Z',
      staffId: 's2',
      action: 'x',
      targetType: 'TENANT',
      targetId: 'a2',
      data: { a: 1 },
      ip: '203.0.113.8',
      requestId: 'r2',
      previousHash: 'p',
    }))
      expect(staffAuditHash({ ...row, [k]: v })).not.toBe(h);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('checkpoint hash covers its head and its predecessor', () => {
    const c = {
      seq: 1n,
      createdAt: new Date('2026-11-04T10:00:00Z'),
      headSeq: 5n,
      headHash: 'a'.repeat(64),
      previousCheckpointHash: null,
    };
    const h = staffCheckpointHash(c);
    expect(staffCheckpointHash({ ...c, headSeq: 6n })).not.toBe(h);
    expect(staffCheckpointHash({ ...c, previousCheckpointHash: 'x' })).not.toBe(
      h,
    );
  });
});
