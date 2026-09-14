import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AppConfig } from '../config/env.validation';
import { SECRET_PROVIDER } from '../database/secret-provider';
import type { SecretProvider } from '../database/secret-provider';
import {
  assertSafeOutboundUrl,
  safeOutboundFetch,
  UnsafeOutboundUrlError,
} from '../common/ssrf/url-safety';
import { parseSsrfAllowedHosts } from '../common/ssrf/ssrf.config';
import {
  signWebhookRequest,
  WEBHOOK_DELIVERY_ID_HEADER,
  WEBHOOK_EVENT_TYPE_HEADER,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_TIMESTAMP_HEADER,
} from './webhook-signing';
import { WebhookDeliveryAttemptFailedError } from './webhook-delivery.errors';

const SecretReferenceDescriptorSchema = z.object({
  provider: z.enum(['ENV', 'OPENBAO', 'CONTROL_DB']),
  reference: z.string().min(1),
});

/**
 * Phase 12a (Webhooks, Section 51). The real HTTP delivery logic, kept
 * independent of Temporal (`WebhookDeliveryActivitiesFactory` is the thin
 * Activity wrapper around this, mirroring `AuditRetentionService`/
 * `AuditRetentionActivitiesFactory`'s split) so it's directly unit-testable
 * and so the Kafka-consumer side never needs a Temporal client just to
 * check "did the last attempt succeed."
 */
@Injectable()
export class WebhookDeliveryService {
  private readonly logger = new Logger(WebhookDeliveryService.name);
  private readonly ssrfAllowedHosts: Set<string>;

  constructor(
    @Inject(SECRET_PROVIDER) private readonly secretProvider: SecretProvider,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {
    this.ssrfAllowedHosts = parseSsrfAllowedHosts(
      configService.get('SSRF_ALLOWED_HOSTS', { infer: true }),
    );
  }

  /**
   * One real delivery attempt: loads the `WebhookDelivery` + its
   * `WebhookEndpoint`, re-validates the outbound URL (SSRF -- see
   * `src/common/ssrf/url-safety.ts`'s doc comment for why this must happen
   * again here, not just once at registration), resolves the signing
   * secret, signs and POSTs the underlying `AuditEvent`'s content, and
   * records the outcome on the `WebhookDelivery` row before returning (on
   * success) or throwing `WebhookDeliveryAttemptFailedError` (on any
   * failure — network error, non-2xx, or SSRF rejection) so Temporal's
   * `WebhookDeliveryWorkflow` retry policy actually retries it.
   *
   * The SSRF check happens in two places, deliberately: once up front
   * (`assertSafeOutboundUrl`, so a bad endpoint fails before the signing
   * secret is ever resolved) and again inside `safeOutboundFetch`, for the
   * request itself and for every redirect hop it follows. A redirect-chain
   * rejection surfaces as an `UnsafeOutboundUrlError` thrown from the
   * request's own `try` and is recorded as a failed attempt like any other
   * network error — never as a delivery to a host that was never checked.
   */
  async attemptDelivery(
    tenantClient: TenantPrismaClient,
    webhookDeliveryId: string,
  ): Promise<{ responseStatus: number | null }> {
    const delivery = await tenantClient.webhookDelivery.findUniqueOrThrow({
      where: { id: webhookDeliveryId },
      include: { webhookEndpoint: true },
    });
    const endpoint = delivery.webhookEndpoint;

    const event = await tenantClient.auditEvent.findUnique({
      where: { id: delivery.eventId },
    });
    if (!event) {
      await this.recordAttempt(tenantClient, webhookDeliveryId, {
        responseStatus: null,
        success: false,
      });
      throw new WebhookDeliveryAttemptFailedError(
        `underlying AuditEvent "${delivery.eventId}" no longer exists`,
      );
    }

    const body = JSON.stringify({
      eventId: event.id,
      eventType: event.eventType,
      timestamp: event.timestamp,
      correlationId: event.correlationId,
      actor: event.actor,
      data: event.data,
    });

    try {
      await assertSafeOutboundUrl(endpoint.url, {
        allowedHosts: this.ssrfAllowedHosts,
      });
    } catch (error) {
      await this.recordAttempt(tenantClient, webhookDeliveryId, {
        responseStatus: null,
        success: false,
      });
      const reason =
        error instanceof UnsafeOutboundUrlError
          ? error.reasonCode
          : 'ssrf_check_failed';
      throw new WebhookDeliveryAttemptFailedError(reason);
    }

    const secretRef = SecretReferenceDescriptorSchema.parse(
      endpoint.secretReference,
    );
    const secret = await this.secretProvider.resolve(secretRef);
    const { signatureHeader, timestampHeader } = signWebhookRequest(
      secret,
      body,
    );

    const timeoutMs = this.configService.get('WEBHOOK_DELIVERY_TIMEOUT_MS', {
      infer: true,
    });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let responseStatus: number | null = null;
    let success = false;
    try {
      // `safeOutboundFetch`, never a bare `fetch`: the pre-flight
      // `assertSafeOutboundUrl` above only vouches for `endpoint.url`
      // itself, and the runtime's default `redirect: 'follow'` would take
      // this delivery anywhere a tenant-registered receiver's
      // `302 Location:` pointed it -- including the cloud instance
      // metadata service -- with no application-level check on the target
      // at all. Every hop is re-validated there instead, and the chain is
      // bounded.
      const response = await safeOutboundFetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          [WEBHOOK_SIGNATURE_HEADER]: signatureHeader,
          [WEBHOOK_TIMESTAMP_HEADER]: timestampHeader,
          [WEBHOOK_EVENT_TYPE_HEADER]: event.eventType,
          [WEBHOOK_DELIVERY_ID_HEADER]: webhookDeliveryId,
        },
        body,
        signal: controller.signal,
        allowedHosts: this.ssrfAllowedHosts,
      });
      responseStatus = response.status;
      success = response.ok;
      // A receiver's response body is never read by anything here (only
      // its status matters), so there is no size limit to impose -- but
      // the body still has to be released, or the socket stays checked out
      // of the connection pool until GC gets to it.
      await response.body?.cancel().catch(() => undefined);
    } catch (error) {
      this.logger.warn(
        `Webhook delivery "${webhookDeliveryId}" attempt failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    } finally {
      clearTimeout(timeout);
    }

    await this.recordAttempt(tenantClient, webhookDeliveryId, {
      responseStatus,
      success,
    });

    if (!success) {
      throw new WebhookDeliveryAttemptFailedError(
        responseStatus !== null ? `HTTP ${responseStatus}` : 'request failed',
      );
    }
    return { responseStatus };
  }

  /** Terminal state after Temporal's retry policy is exhausted — called once by `WebhookDeliveryWorkflow`'s own catch, never by `attemptDelivery` itself. */
  async markFailed(
    tenantClient: TenantPrismaClient,
    webhookDeliveryId: string,
  ): Promise<void> {
    await tenantClient.webhookDelivery.update({
      where: { id: webhookDeliveryId },
      data: { status: 'FAILED' },
    });
  }

  private async recordAttempt(
    tenantClient: TenantPrismaClient,
    webhookDeliveryId: string,
    outcome: { responseStatus: number | null; success: boolean },
  ): Promise<void> {
    await tenantClient.webhookDelivery.update({
      where: { id: webhookDeliveryId },
      data: {
        attempts: { increment: 1 },
        lastAttemptAt: new Date(),
        responseStatus: outcome.responseStatus,
        ...(outcome.success ? { status: 'SUCCESS' } : {}),
      },
    });
  }
}
