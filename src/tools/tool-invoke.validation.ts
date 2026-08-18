import { z } from 'zod';

/** `POST /agent/v1/tools/invoke`'s request body — see docs/tool-gateway.md. */
export const ToolInvokeRequestSchema = z.object({
  taskId: z.string().min(1),
  toolId: z.string().min(1).max(128),
  actionId: z.string().min(1).max(128),
  resource: z.string().min(1).max(2048),
  /** The tool action's own arguments — opaque to this schema, validated against `ToolAction.inputSchema` (JSON Schema) inside the resolved adapter before any call is made. */
  params: z.unknown(),
});

export type ToolInvokeRequest = z.infer<typeof ToolInvokeRequestSchema>;
