import { z } from 'zod';

/** Body for every `POST /.../kill-switch` activation endpoint — `reason` is optional (unlike `RevokeAgentRequestSchema`'s required `reason`) since an emergency kill-switch activation may need to happen before there's time to write one down; still capped for storage hygiene. */
export const ActivateKillSwitchRequestSchema = z.object({
  reason: z.string().min(1).max(500).optional(),
});
export type ActivateKillSwitchRequest = z.infer<
  typeof ActivateKillSwitchRequestSchema
>;

/** Body for every `POST /.../kill-switch/deactivate` endpoint — no fields required; who deactivated it is already known from `AuthContext`. */
export const DeactivateKillSwitchRequestSchema = z.object({});
export type DeactivateKillSwitchRequest = z.infer<
  typeof DeactivateKillSwitchRequestSchema
>;
