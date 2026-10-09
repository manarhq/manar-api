import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * Signed heartbeat to manar-fleet (ADR-0010). Off by default: nothing is sent unless
 * FLEET_HEARTBEAT_URL is set. The Ed25519 signing key lives in OpenBao KV at
 * FLEET_HEARTBEAT_KEY_PATH (`pnpm manar fleet:keygen` creates it).
 */
export const FleetHeartbeatConfigSchema = z.object({
  FLEET_HEARTBEAT_URL: optional,
  FLEET_DEPLOYMENT_ID: optional,
  FLEET_HEARTBEAT_INTERVAL_MINUTES: z.coerce
    .number()
    .int()
    .min(1)
    .max(1440)
    .default(5),
  FLEET_HEARTBEAT_KEY_PATH: z
    .string()
    .min(1)
    .default('fleet/heartbeat-signing-key'),
  /** JSON written by the backup job: {status, lastBackupAt, lastRestoreTestAt}. Unset = unknown. */
  FLEET_BACKUP_STATUS_FILE: optional,
  /** Set at image build (see Dockerfile). */
  MANAR_GIT_SHA: optional,
});

export type FleetHeartbeatConfig = z.infer<typeof FleetHeartbeatConfigSchema>;
