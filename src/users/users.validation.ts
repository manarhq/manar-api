import { z } from 'zod';
import { ROLES } from '../auth/roles';

/** `POST /users/:id/role-bindings`'s request body. */
export const GrantRoleRequestSchema = z.object({
  role: z.enum(ROLES),
});
export type GrantRoleRequest = z.infer<typeof GrantRoleRequestSchema>;
