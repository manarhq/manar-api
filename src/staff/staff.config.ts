import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * The staff listener (DESK spec §5, AC-6). Off unless STAFF_ENABLED=true, so existing deployments
 * are unchanged until the infra change sets it. When on, the issuer and Entra tenant are required.
 */
export const StaffConfigSchema = z.object({
  STAFF_ENABLED: z.enum(['true', 'false']).default('false'),
  STAFF_PORT: z.coerce.number().int().min(1).max(65535).default(3200),
  /** Exact issuer of staff tokens: the vax-staff realm, e.g. http://localhost:8081/realms/vax-staff. */
  STAFF_OIDC_ISSUER: optional,
  /** Client staff tokens are issued to (`azp`). */
  STAFF_OIDC_CLIENT_ID: z.string().min(1).default('manar-admin'),
  /** Audience the vax-staff realm adds for CORE. */
  STAFF_API_AUDIENCE: z.string().min(1).default('manar-api-staff'),
  /** Fixio's Entra tenant id; staff tokens must carry it as `entra_tid` (AC-44). */
  STAFF_ENTRA_TENANT_ID: optional,
  /** HMAC key for restriction fingerprints (spec §9.5). 32+ characters, from OpenBao or Key Vault. */
  RESTRICTION_FINGERPRINT_KEY: optional,
  /** Turnstile secret for customer appeals (Key Vault `turnstile-secret-key`). */
  TURNSTILE_SECRET_KEY: optional,
  /** Chain id of the staff audit log's signing key and OpenBao anchor. */
  STAFF_AUDIT_CHAIN_ID: z.string().min(1).default('staff-audit'),
});

export type StaffConfig = z.infer<typeof StaffConfigSchema>;

export function staffConfigIssues(
  c: StaffConfig & { NODE_ENV?: string },
): string[] {
  const issues: string[] = [];
  if (c.STAFF_ENABLED === 'true') {
    if (!c.STAFF_OIDC_ISSUER)
      issues.push('STAFF_OIDC_ISSUER is required when STAFF_ENABLED=true');
    if (!c.STAFF_ENTRA_TENANT_ID)
      issues.push('STAFF_ENTRA_TENANT_ID is required when STAFF_ENABLED=true');
  }
  if (
    c.RESTRICTION_FINGERPRINT_KEY &&
    c.RESTRICTION_FINGERPRINT_KEY.length < 32
  )
    issues.push('RESTRICTION_FINGERPRINT_KEY must be at least 32 characters');
  if (
    c.NODE_ENV === 'production' &&
    c.STAFF_ENABLED === 'true' &&
    !c.RESTRICTION_FINGERPRINT_KEY
  )
    issues.push(
      'RESTRICTION_FINGERPRINT_KEY is required in production when STAFF_ENABLED=true',
    );
  return issues;
}
