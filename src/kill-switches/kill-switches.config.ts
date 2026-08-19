import { z } from 'zod';

/**
 * Kill-switch phase (Section 32) config. `PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`
 * gates `POST /kill-switches/platform`(`/deactivate`) in addition to
 * `JwtAuthGuard`+`RolesGuard` — see `PlatformOperatorGuard`'s doc comment
 * for why a per-tenant role alone must never be sufficient to flip a
 * switch that denies every tenant at once (Section 11's "no
 * application-level super admin" principle).
 */
export const KillSwitchesConfigSchema = z.object({
  /**
   * A separate, non-tenant-scoped operator credential — never distributed
   * through any tenant's Keycloak realm/RBAC. No production default — the
   * `.env.example`/`.env` dev value is only ever a placeholder, same
   * posture as this codebase's other dev-only secrets (see
   * `ApprovalsConfigSchema.APPROVAL_GRANT_SIGNING_SECRET`).
   */
  PLATFORM_KILL_SWITCH_OPERATOR_TOKEN: z.string().min(16),
});

export type KillSwitchesConfig = z.infer<typeof KillSwitchesConfigSchema>;
