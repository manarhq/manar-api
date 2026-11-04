import { staffAuditHash } from './staff-audit.service';

describe('staffAuditHash', () => {
  const row = {
    seq: '1',
    at: '2026-11-04T10:00:00.000Z',
    staffId: 's1',
    action: 'person.viewed',
    targetType: 'ACCOUNT',
    targetId: 'a1',
    data: { b: 2, a: 1 },
  };

  it('is stable for key order and changes with any field or the previous hash', () => {
    const h = staffAuditHash(null, row);
    expect(staffAuditHash(null, { ...row, data: { a: 1, b: 2 } })).toBe(h);
    expect(staffAuditHash(null, { ...row, targetId: 'a2' })).not.toBe(h);
    expect(staffAuditHash('x', row)).not.toBe(h);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
});
