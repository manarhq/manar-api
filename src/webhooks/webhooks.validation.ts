import { z } from 'zod';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';

/** Every real event type from Phase 9a's catalog (`src/audit/audit-event-types.ts`) — the only values a `WebhookEndpoint.subscribedEventTypes` entry may name. Rejects an unknown/mistyped event type at registration time rather than silently subscribing to nothing. */
const KNOWN_EVENT_TYPES = Object.values(AUDIT_EVENT_TYPES) as [
  string,
  ...string[],
];

const SubscribedEventTypesSchema = z
  .array(z.enum(KNOWN_EVENT_TYPES))
  .min(1, 'subscribedEventTypes must name at least one event type');

/** Body for `POST /webhooks`. */
export const CreateWebhookEndpointRequestSchema = z.object({
  url: z.string().min(1).max(2048),
  subscribedEventTypes: SubscribedEventTypesSchema,
  enabled: z.boolean().optional(),
});
export type CreateWebhookEndpointRequest = z.infer<
  typeof CreateWebhookEndpointRequestSchema
>;

/** Body for `PATCH /webhooks/:id` — every field optional, only what's provided is updated. */
export const UpdateWebhookEndpointRequestSchema = z.object({
  url: z.string().min(1).max(2048).optional(),
  subscribedEventTypes: SubscribedEventTypesSchema.optional(),
  enabled: z.boolean().optional(),
});
export type UpdateWebhookEndpointRequest = z.infer<
  typeof UpdateWebhookEndpointRequestSchema
>;
