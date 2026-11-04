import type { StaffPermission } from '../rbac/permissions';

export type RestrictionKind = 'WARNING' | 'SUSPEND' | 'BAN';
export const CATEGORIES = [
  'terms_violation',
  'abuse_or_attack',
  'fraud_or_payment',
  'spam_or_bulk_signups',
  'security_risk',
  'legal_request',
  'ban_evasion',
  'other_policy',
] as const;
export type Category = (typeof CATEGORIES)[number];
export const DURATIONS = {
  '1h': 3_600_000,
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
} as const;
export type Duration = keyof typeof DURATIONS;
export const WARNING_WINDOW_MS = 48 * 3_600_000;
export const MIN_NOTE = 20;

export type PersonStatus =
  'ACTIVE' | 'WARNED' | 'SUSPENDED' | 'BANNED' | 'DELETION_PENDING';

interface RestrictionRow {
  kind: RestrictionKind;
  startsAt: Date;
  until?: Date | null;
  liftedAt?: Date | null;
}

/** Spec §9.1: expiry is checked at read time, so a stalled job never extends a suspension. */
export function isInForce(r: RestrictionRow, now: Date): boolean {
  if (r.liftedAt || r.startsAt > now) return false;
  if (r.kind === 'SUSPEND') return !!r.until && r.until > now;
  return true;
}

export function personStatus(
  rows: RestrictionRow[],
  now: Date,
  extra: { deletionPending?: boolean } = {},
): PersonStatus {
  const live = rows.filter((r) => isInForce(r, now));
  if (live.some((r) => r.kind === 'BAN')) return 'BANNED';
  if (live.some((r) => r.kind === 'SUSPEND')) return 'SUSPENDED';
  if (extra.deletionPending) return 'DELETION_PENDING';
  if (live.some((r) => r.kind === 'WARNING')) return 'WARNED';
  return 'ACTIVE';
}

export type Plan =
  | { action: 'apply'; until?: Date }
  | {
      action: 'propose';
      changeKind: 'suspend_proposal' | 'immediate_restriction';
    }
  | { refused: string };

/**
 * Spec §9.1 to §9.3 as one pure decision: who may warn, suspend or ban, and when a paying
 * customer needs a warning first (AC-22). The caller's permissions come from OpenFGA.
 */
export function planRestriction(i: {
  kind: RestrictionKind;
  duration?: Duration;
  category: Category;
  note: string;
  immediate?: boolean;
  caller: { permissions: ReadonlySet<StaffPermission> };
  target: {
    paying: boolean;
    warnedAt?: Date | null;
    current?: RestrictionKind | null;
  };
  now: Date;
}): Plan {
  const has = (p: StaffPermission) => i.caller.permissions.has(p);
  if (!(CATEGORIES as readonly string[]).includes(i.category))
    return { refused: 'bad_category' };
  if (i.note.trim().length < MIN_NOTE) return { refused: 'note_too_short' };
  if (i.kind === 'WARNING')
    return has('restrict.warn')
      ? { action: 'apply' }
      : { refused: 'permission_required' };
  if (i.target.current === 'BAN') return { refused: 'already_banned' };
  let until: Date | undefined;
  if (i.kind === 'SUSPEND') {
    if (!i.duration || !(i.duration in DURATIONS))
      return { refused: 'bad_duration' };
    until = new Date(i.now.getTime() + DURATIONS[i.duration]);
    if (!has('restrict.suspend'))
      return has('restrict.suspend.propose')
        ? { action: 'propose', changeKind: 'suspend_proposal' }
        : { refused: 'permission_required' };
  } else if (!has('restrict.ban')) return { refused: 'permission_required' };

  if (i.target.paying) {
    const warnedLongEnough =
      !!i.target.warnedAt &&
      i.now.getTime() - i.target.warnedAt.getTime() >= WARNING_WINDOW_MS;
    const protective = i.kind === 'SUSPEND' && i.category === 'security_risk';
    if (!warnedLongEnough && !protective)
      return i.immediate
        ? { action: 'propose', changeKind: 'immediate_restriction' }
        : { refused: 'warning_required' };
  }
  return until ? { action: 'apply', until } : { action: 'apply' };
}

const DUBAI_OFFSET_MS = 4 * 3_600_000; // UTC+4 all year
const DAY = 86_400_000;

/** Due time of an appeal: 3 business days later, Monday to Friday in Asia/Dubai (AC-23). */
export function dueAt(submittedAt: Date): Date {
  let local = submittedAt.getTime() + DUBAI_OFFSET_MS;
  const dow = () => new Date(local).getUTCDay(); // 0 Sunday, 6 Saturday
  if (dow() === 6 || dow() === 0) {
    while (dow() !== 1) local += DAY;
    local = Math.floor(local / DAY) * DAY; // Monday 00:00 Dubai
  }
  for (let added = 0; added < 3;) {
    local += DAY;
    if (dow() !== 6 && dow() !== 0) added++;
  }
  return new Date(local - DUBAI_OFFSET_MS);
}
