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
  /** ADR-0009: at most this many agents quarantined by one agent per window, server side (defaults 5 per 10 min, in `AgentQuarantineService`). */
  QUARANTINE_MAX_PER_AGENT: z.coerce.number().int().positive().optional(),
  QUARANTINE_WINDOW_MS: z.coerce.number().int().positive().optional(),
});

export type KillSwitchesConfig = z.infer<typeof KillSwitchesConfigSchema>;
