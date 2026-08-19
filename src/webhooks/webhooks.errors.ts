/** Thrown by `WebhookRegistryService` for a `WebhookEndpoint` id that doesn't resolve for this tenant. */
export class WebhookEndpointNotFoundError extends Error {
  constructor(id: string) {
    super(`WebhookEndpoint "${id}" was not found`);
    this.name = 'WebhookEndpointNotFoundError';
  }
}
