import { z } from 'zod';

/**
 * `POST /agent/v1/tools/invoke`'s request body — see docs/tool-gateway.md
 * and, for `grantToken`, docs/approvals.md (Phase 8). `grantToken` is the
 * signed `AuthorizationGrant` token returned by `GET /agent/v1/approvals/:id`
 * once a `PENDING_APPROVAL` request is `APPROVED` — an agent's retried
 * request carries the *exact same* `taskId`/`toolId`/`actionId`/`resource`/
 * `params` as its original request, plus this field. Its presence (not any
 * separate flag) is what routes this request onto the grant-validation
 * path instead of `AuthorizationService.authorize`'s normal pipeline — see
 * `ToolInvokeController`.
 */
export const ToolInvokeRequestSchema = z.object({
  taskId: z.string().min(1),
  toolId: z.string().min(1).max(128),
  actionId: z.string().min(1).max(128),
  resource: z.string().min(1).max(2048),
  /** The tool action's own arguments — opaque to this schema, validated against `ToolAction.inputSchema` (JSON Schema) inside the resolved adapter before any call is made. */
  params: z.unknown(),
  grantToken: z.string().min(1).optional(),
});

export type ToolInvokeRequest = z.infer<typeof ToolInvokeRequestSchema>;
