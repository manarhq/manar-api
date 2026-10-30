export const PLANS = [
  'free',
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

export const TRIAL_DAYS = 30;
/** Devices included per billable user on the Company plan; every one beyond is an extra device. */
export const DEVICES_PER_USER = 3;

export const FREE_LIMITS: Limits = {
  devices: 3,
  agents: 10,
  cloudAgents: 1,
  auditDays: 30,
};

/** Enterprise limits come from the signed licence, not from here. */
export const PLAN_TABLE: Record<
  Exclude<PlanName, 'enterprise'>,
  { limits: Limits; features: string[] }
> = {
  free: { limits: FREE_LIMITS, features: [] },
  pro: {
    limits: { devices: 10, agents: null, cloudAgents: 5, auditDays: 365 },
    features: ['tls_inspection', 'priority_support'],
  },
  // A trial caps devices at 25; a paid Company workspace pays per extra device instead.
  company_trial: {
    limits: { devices: 25, agents: null, cloudAgents: null, auditDays: 365 },
    features: COMPANY_FEATURES,
  },
  company: {
    limits: { devices: null, agents: null, cloudAgents: null, auditDays: 365 },
    features: COMPANY_FEATURES,
  },
};
