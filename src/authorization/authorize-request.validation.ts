import { z } from 'zod';

/** `POST /agent/v1/authorize` request body. */
export const AuthorizeRequestSchema = z.object({
  taskId: z.string().min(1),
  toolId: z.string().min(1).max(128),
  actionId: z.string().min(1).max(128),
  resource: z.string().min(1).max(2048),
});
export type AuthorizeRequest = z.infer<typeof AuthorizeRequestSchema>;
