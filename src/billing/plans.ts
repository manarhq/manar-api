/**
 * Plans, limits and allowances: pay-as-you-go hybrid pricing (workspace spec
 * docs/superpowers/specs/2026-11-04-payg-pricing-design.md, founder decision 4 Nov 10:18).
 */
export const PLANS = [
  'free',
  'trial',
  'pro',
  'company_trial',
  'company',
  'enterprise',
] as const;
export type PlanName = (typeof PLANS)[number];

export type LimitName = 'devices' | 'agents' | 'cloudAgents';

/** `null` = unlimited. */
export interface Limits {
  devices: number | null;
  agents: number | null;
  cloudAgents: number | null;
  auditDays: number | null;
}

/** Included per month (per seat on Company). Above it, paid plans spend credits; Free stops. */
export interface Allowance {
  ai: number;
  cloudMinutes: number;
}

/** Features that only Enterprise has (spec 7a): Hub/federation, air-gapped, gov, TPM, compliance packs. */
export const ENTERPRISE_ONLY_FEATURES = [
  'hub',
  'air_gapped',
  'gov',
  'tpm',
  'compliance_packs',
] as const;

const COMPANY_FEATURES = [
  'tls_inspection',
  'priority_support',
  'ad_sync',
  'sso',
];

/** Company trial (card required, not charged during it; then it converts to paid). */
export const TRIAL_DAYS = 14;
/** Personal trial: no card, unlocks only "up to 3 devices". */
export const PERSONAL_TRIAL_DAYS = 14;

/** Pro includes this many active devices; each further active device is billed. */
export const PRO_INCLUDED_DEVICES = 2;
/** Company bills at least this many seats a month, and commits at least this many a year. */
export const COMPANY_MIN_SEATS = 3;
/** Days online in a calendar month (UTC) that make a device or seat active. */
export const ACTIVE_DAYS = 3;

/** $5 buys 1,000 credits; 1 credit = 1 AI action = 1 cloud-agent minute. */
export const CREDITS_PER_PACK = 1000;
export const PACK_CENTS = 500;
export const CREDIT_VALID_MONTHS = 12;
/** Pro's default overage cap: $20 a month. */
export const PRO_DEFAULT_CAP_CREDITS = 4000;
/** Company's cap until an admin sets one (founder question Q2): $50 a month. */
export const COMPANY_DEFAULT_CAP_CREDITS = 10000;
/** Auto top-up: 2 packs ($10) when the balance is under 400 credits ($2), at most 3 a month. */
export const TOP_UP_PACKS = 2;
export const TOP_UP_BELOW_CREDITS = 400;
export const TOP_UP_MAX_PER_MONTH = 3;

export const FREE_LIMITS: Limits = {
  devices: 1,
  agents: 10,
  cloudAgents: 0,
  auditDays: 30,
};
const FREE_ALLOWANCE: Allowance = { ai: 20, cloudMinutes: 0 };
const PAID_ALLOWANCE: Allowance = { ai: 300, cloudMinutes: 300 };

/** Enterprise limits come from the signed licence, not from here. */
export const PLAN_TABLE: Record<
  Exclude<PlanName, 'enterprise'>,
  { limits: Limits; features: string[]; allowance: Allowance }
> = {
  free: { limits: FREE_LIMITS, features: [], allowance: FREE_ALLOWANCE },
  // Only "up to 3 devices"; AI, history and cloud agents stay as Free.
  trial: {
    limits: { ...FREE_LIMITS, devices: 3 },
    features: [],
    allowance: FREE_ALLOWANCE,
  },
  // Devices are not capped: active ones beyond 2 are billed.
  pro: {
    limits: { devices: null, agents: null, cloudAgents: null, auditDays: 365 },
    features: ['tls_inspection', 'priority_support'],
    allowance: PAID_ALLOWANCE,
  },
  company_trial: {
    limits: { devices: 25, agents: null, cloudAgents: null, auditDays: 365 },
    features: COMPANY_FEATURES,
    allowance: PAID_ALLOWANCE,
  },
  company: {
    limits: { devices: null, agents: null, cloudAgents: null, auditDays: 365 },
    features: COMPANY_FEATURES,
    allowance: PAID_ALLOWANCE,
  },
};

/** Plans whose allowance is per seat and pooled. */
export const SEAT_PLANS: ReadonlySet<PlanName> = new Set([
  'company_trial',
  'company',
]);

/** `2026-11` (UTC). */
export function monthOf(at: Date = new Date()): string {
  return at.toISOString().slice(0, 7);
}
