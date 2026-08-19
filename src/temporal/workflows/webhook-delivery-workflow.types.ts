export interface WebhookDeliveryWorkflowInput {
  tenantId: string;
  webhookDeliveryId: string;
}

export interface WebhookDeliveryWorkflowResult {
  outcome: 'DELIVERED' | 'FAILED';
}
