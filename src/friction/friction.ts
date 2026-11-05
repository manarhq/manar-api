/** Decision 38: a workspace stays under this many prompts per developer per day, on average. */
export const FRICTION_BUDGET = 5;

export interface FrictionRow {
  day: Date;
  subject: string;
  prompts: number;
  approvals: number;
  denies: number;
  expired: number;
  deniedLaterApproved: number;
  answered: number;
  answerMs: number;
  blockedMs: number;
}

export interface FrictionNumbers {
  prompts: number;
  approvals: number;
  denies: number;
  expired: number;
  deniedLaterApproved: number;
  answered: number;
  /** Mean prompt-to-answer time over the answered prompts, in seconds (0 when none). */
  avgAnswerSeconds: number;
  /** Time tools waited on a person, in minutes. */
  blockedMinutes: number;
}

const round1 = (n: number) => Math.round(n * 10) / 10;

export function numbers(rows: FrictionRow[]): FrictionNumbers {
  const sum = (k: keyof FrictionRow) =>
    rows.reduce((a, r) => a + (r[k] as number), 0);
  const answered = sum('answered');
  return {
    prompts: sum('prompts'),
    approvals: sum('approvals'),
    denies: sum('denies'),
    expired: sum('expired'),
    deniedLaterApproved: sum('deniedLaterApproved'),
    answered,
    avgAnswerSeconds: answered ? round1(sum('answerMs') / answered / 1000) : 0,
    blockedMinutes: round1(sum('blockedMs') / 60_000),
  };
}

/** `YYYY-MM-DD` of a UTC day. */
export const dayKey = (d: Date) => d.toISOString().slice(0, 10);

/** The UTC days from `days - 1` days before `now` up to and including today. */
export function dayRange(now: Date, days: number): Date[] {
  const today = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  );
  return Array.from(
    { length: days },
    (_, i) => new Date(today - (days - 1 - i) * 86_400_000),
  );
}

/**
 * Prompts per developer per day over the window. `developers` is the number of people who own an
 * enrolled device (at least 1), so a quiet developer lowers the average, as they should.
 */
export function promptsPerDeveloperPerDay(
  prompts: number,
  developers: number,
  days: number,
): number {
  return round1(prompts / (Math.max(1, developers) * Math.max(1, days)));
}

export function overBudget(avgPerDeveloperPerDay: number): boolean {
  return avgPerDeveloperPerDay > FRICTION_BUDGET;
}
