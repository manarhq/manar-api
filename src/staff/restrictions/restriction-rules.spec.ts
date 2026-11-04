import { STAFF_PERMISSIONS, type StaffPermission } from '../rbac/permissions';
import {
  dueAt,
  isInForce,
  personStatus,
  planRestriction,
} from './restriction-rules';

const now = new Date('2026-11-04T10:00:00Z');
const perms = (...p: StaffPermission[]) => new Set<StaffPermission>(p);
const ALL = new Set<StaffPermission>(STAFF_PERMISSIONS);
const note = 'Bulk sign-ups from one device in 40 minutes, see MNR-7KQ2XD.';
const free = { paying: false, warnedAt: null, current: null };

describe('isInForce', () => {
  const base = { startsAt: new Date(now.getTime() - 60_000), liftedAt: null };
  it('a suspension ends at its until, with no job (read-time check)', () => {
    expect(
      isInForce(
        { ...base, kind: 'SUSPEND', until: new Date(now.getTime() + 1) },
        now,
      ),
    ).toBe(true);
    expect(
      isInForce(
        { ...base, kind: 'SUSPEND', until: new Date(now.getTime() - 1) },
        now,
      ),
    ).toBe(false);
    expect(isInForce({ ...base, kind: 'SUSPEND', until: now }, now)).toBe(
      false,
    );
    expect(isInForce({ ...base, kind: 'SUSPEND', until: null }, now)).toBe(
      false,
    );
  });
  it('a ban lasts until lifted', () => {
    expect(isInForce({ ...base, kind: 'BAN', until: null }, now)).toBe(true);
    expect(
      isInForce({ ...base, kind: 'BAN', until: null, liftedAt: now }, now),
    ).toBe(false);
  });
});

describe('personStatus', () => {
  it('ban beats suspension beats warning', () => {
    const r = (kind: 'WARNING' | 'SUSPEND' | 'BAN') => ({
      kind,
      startsAt: new Date(0),
      until: kind === 'SUSPEND' ? new Date(now.getTime() + 1000) : null,
      liftedAt: null,
    });
    expect(personStatus([r('WARNING'), r('SUSPEND'), r('BAN')], now)).toBe(
      'BANNED',
    );
    expect(personStatus([r('WARNING'), r('SUSPEND')], now)).toBe('SUSPENDED');
    expect(personStatus([r('WARNING')], now)).toBe('WARNED');
    expect(personStatus([], now, { deletionPending: true })).toBe(
      'DELETION_PENDING',
    );
    expect(personStatus([], now)).toBe('ACTIVE');
  });
});

describe('planRestriction', () => {
  it('needs an internal note of at least 20 characters', () => {
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '24h',
        category: 'terms_violation',
        note: 'too short',
        caller: { permissions: ALL },
        target: free,
        now,
      }),
    ).toEqual({ refused: 'note_too_short' });
  });
  it('allows only the four suspension lengths', () => {
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '48h' as never,
        category: 'terms_violation',
        note,
        caller: { permissions: ALL },
        target: free,
        now,
      }),
    ).toEqual({ refused: 'bad_duration' });
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '7d',
        category: 'terms_violation',
        note,
        caller: { permissions: ALL },
        target: free,
        now,
      }),
    ).toEqual({
      action: 'apply',
      until: new Date(now.getTime() + 7 * 86_400_000),
    });
  });
  it('Admin suspends; Trust & Safety proposes; nobody else may', () => {
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '1h',
        category: 'spam_or_bulk_signups',
        note,
        caller: { permissions: perms('restrict.suspend') },
        target: free,
        now,
      }),
    ).toMatchObject({ action: 'apply' });
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '1h',
        category: 'spam_or_bulk_signups',
        note,
        caller: { permissions: perms('restrict.suspend.propose') },
        target: free,
        now,
      }),
    ).toEqual({ action: 'propose', changeKind: 'suspend_proposal' });
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '1h',
        category: 'spam_or_bulk_signups',
        note,
        caller: { permissions: perms('people.view') },
        target: free,
        now,
      }),
    ).toEqual({ refused: 'permission_required' });
  });
  it('a ban needs restrict.ban (Owner)', () => {
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'abuse_or_attack',
        note,
        caller: { permissions: perms('restrict.suspend') },
        target: free,
        now,
      }),
    ).toEqual({ refused: 'permission_required' });
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'abuse_or_attack',
        note,
        caller: { permissions: ALL },
        target: free,
        now,
      }),
    ).toEqual({ action: 'apply' });
  });
  it('paying customers: warning first, 48 hours, unless security_risk or a second person', () => {
    const paying = { paying: true, warnedAt: null, current: null };
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'abuse_or_attack',
        note,
        caller: { permissions: ALL },
        target: paying,
        now,
      }),
    ).toEqual({ refused: 'warning_required' });
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'abuse_or_attack',
        note,
        immediate: true,
        caller: { permissions: ALL },
        target: paying,
        now,
      }),
    ).toEqual({ action: 'propose', changeKind: 'immediate_restriction' });
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '24h',
        category: 'security_risk',
        note,
        caller: { permissions: ALL },
        target: paying,
        now,
      }),
    ).toMatchObject({ action: 'apply' });
    const warned47h = {
      ...paying,
      warnedAt: new Date(now.getTime() - 47 * 3_600_000),
    };
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'abuse_or_attack',
        note,
        caller: { permissions: ALL },
        target: warned47h,
        now,
      }),
    ).toEqual({ refused: 'warning_required' });
    const warned49h = {
      ...paying,
      warnedAt: new Date(now.getTime() - 49 * 3_600_000),
    };
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'abuse_or_attack',
        note,
        caller: { permissions: ALL },
        target: warned49h,
        now,
      }),
    ).toEqual({ action: 'apply' });
    expect(
      planRestriction({
        kind: 'WARNING',
        category: 'terms_violation',
        note,
        caller: { permissions: perms('restrict.warn') },
        target: paying,
        now,
      }),
    ).toEqual({ action: 'apply' });
  });
  it('refuses to stack: a banned person cannot be suspended, a ban replaces a suspension', () => {
    expect(
      planRestriction({
        kind: 'SUSPEND',
        duration: '1h',
        category: 'terms_violation',
        note,
        caller: { permissions: ALL },
        target: { ...free, current: 'BAN' },
        now,
      }),
    ).toEqual({ refused: 'already_banned' });
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'terms_violation',
        note,
        caller: { permissions: ALL },
        target: { ...free, current: 'SUSPEND' },
        now,
      }),
    ).toEqual({ action: 'apply' });
  });
  it('rejects an unknown category', () => {
    expect(
      planRestriction({
        kind: 'BAN',
        category: 'because' as never,
        note,
        caller: { permissions: ALL },
        target: free,
        now,
      }),
    ).toEqual({ refused: 'bad_category' });
  });
});

describe('dueAt (3 business days, Monday to Friday, Asia/Dubai; AC-23)', () => {
  it('Thursday 18:00 Dubai is due Tuesday 18:00 Dubai', () => {
    expect(dueAt(new Date('2026-11-05T14:00:00Z'))).toEqual(
      new Date('2026-11-10T14:00:00Z'),
    );
  });
  it('Monday 09:00 is due Thursday 09:00', () => {
    expect(dueAt(new Date('2026-11-02T05:00:00Z'))).toEqual(
      new Date('2026-11-05T05:00:00Z'),
    );
  });
  it('a Saturday arrival counts from Monday 00:00 Dubai', () => {
    expect(dueAt(new Date('2026-11-07T12:00:00Z'))).toEqual(
      new Date('2026-11-11T20:00:00Z'),
    );
  });
});
