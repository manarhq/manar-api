import { AsyncLocalStorage } from 'node:async_hooks';

export const CORRELATION_ID_HEADER = 'x-correlation-id';

export interface CorrelationIdContext {
  correlationId: string;
}

/**
 * Request-scoped correlation ID, propagated via AsyncLocalStorage so any
 * code running within a request's async chain (services, the Winston
 * logger format) can read it without threading it through every function
 * signature.
 */
export const correlationIdStore = new AsyncLocalStorage<CorrelationIdContext>();

export function getCorrelationId(): string | undefined {
  return correlationIdStore.getStore()?.correlationId;
}
