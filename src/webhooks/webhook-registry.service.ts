import { randomBytes, randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AppConfig } from '../config/env.validation';
import { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import { assertSafeOutboundUrl } from '../common/ssrf/url-safety';
import { parseSsrfAllowedHosts } from '../common/ssrf/ssrf.config';
import { WebhookEndpointNotFoundError } from './webhooks.errors';
import type {
  CreateWebhookEndpointRequest,
  UpdateWebhookEndpointRequest,
} from './webhooks.validation';

/** The KV v2 path (relative to `OPENBAO_KV_MOUNT_PATH`) a given `WebhookEndpoint`'s signing secret is stored at — mirrors `OpenBaoSecretProvider`'s "one opaque string under the fixed key `value`" convention. */
function webhookSecretKvPath(webhookEndpointId: string): string {
  return `webhooks/${webhookEndpointId}`;
}

/** The subset of fields ever returned to a caller — deliberately excludes `secretReference` (Section 51: the secret is generated once, at creation, and never re-exposed; see `WebhookEndpointCreatedDto` for the one-time exception). */
export interface WebhookEndpointSummary {
  id: string;
  url: string;
  subscribedEventTypes: string[];
  enabled: boolean;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Phase 12a (Webhooks, Section 51) admin CRUD, mirroring the same
 * "providers-only service, controller-gated separately" split every other
 * admin surface in this codebase uses (`KillSwitchService`/
 * `KillSwitchesController`). Owns both the `WebhookEndpoint` row lifecycle
 * AND the signing-secret lifecycle (generate at creation, write it to
 * OpenBao, never persist or return the plaintext value again) — unlike
 * `Tool.credentialReference`, which always names a *pre-existing* external
 * credential, a webhook's secret doesn't exist until Manar itself creates
 * it, so this service is the one place that ever calls
 * `OpenBaoKvClient.writeSecret` outside test fixtures.
 */
@Injectable()
export class WebhookRegistryService {
  private readonly ssrfAllowedHosts: Set<string>;

  constructor(
    private readonly openBaoKvClient: OpenBaoKvClient,
    configService: ConfigService<AppConfig, true>,
  ) {
    this.ssrfAllowedHosts = parseSsrfAllowedHosts(
      configService.get('SSRF_ALLOWED_HOSTS', { infer: true }),
    );
  }

  /**
   * Creates the `WebhookEndpoint` row and generates+stores its signing
   * secret. Returns the secret in plaintext exactly this once — the only
   * time it's ever available outside OpenBao itself, matching common
   * "shown once at creation" secret-management UX (there is no
   * `GET`-the-secret-back endpoint).
   */
  async create(
    tenantClient: TenantPrismaClient,
    input: CreateWebhookEndpointRequest & { createdBy: string },
  ): Promise<{ endpoint: WebhookEndpointSummary; secret: string }> {
    // Phase 12a SSRF protection: rejected at registration time (this
    // call) AND re-validated at delivery time (`WebhookDeliveryService`) —
    // see src/common/ssrf/url-safety.ts's doc comment for why both checks
    // matter (DNS rebinding).
    await assertSafeOutboundUrl(input.url, {
      allowedHosts: this.ssrfAllowedHosts,
    });

    const id = randomUUID();
    const secret = randomBytes(32).toString('hex');
    await this.openBaoKvClient.writeSecret(webhookSecretKvPath(id), {
      value: secret,
    });

    const row = await tenantClient.webhookEndpoint.create({
      data: {
        id,
        url: input.url,
        subscribedEventTypes: input.subscribedEventTypes,
        enabled: input.enabled ?? true,
        createdBy: input.createdBy,
        secretReference: {
          provider: 'OPENBAO',
          reference: webhookSecretKvPath(id),
        },
      },
    });

    return { endpoint: this.toSummary(row), secret };
  }

  async list(
    tenantClient: TenantPrismaClient,
  ): Promise<WebhookEndpointSummary[]> {
    const rows = await tenantClient.webhookEndpoint.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((row) => this.toSummary(row));
  }

  async get(
    tenantClient: TenantPrismaClient,
    id: string,
  ): Promise<WebhookEndpointSummary> {
    const row = await tenantClient.webhookEndpoint.findUnique({
      where: { id },
    });
    if (!row) throw new WebhookEndpointNotFoundError(id);
    return this.toSummary(row);
  }

  async update(
    tenantClient: TenantPrismaClient,
    id: string,
    input: UpdateWebhookEndpointRequest,
  ): Promise<WebhookEndpointSummary> {
    const existing = await tenantClient.webhookEndpoint.findUnique({
      where: { id },
    });
    if (!existing) throw new WebhookEndpointNotFoundError(id);

    if (input.url !== undefined) {
      // Re-validated here too -- an update is a fresh registration of a
      // URL, not exempt from the same SSRF check `create` applies.
      await assertSafeOutboundUrl(input.url, {
        allowedHosts: this.ssrfAllowedHosts,
      });
    }

    const row = await tenantClient.webhookEndpoint.update({
      where: { id },
      data: {
        ...(input.url !== undefined ? { url: input.url } : {}),
        ...(input.subscribedEventTypes !== undefined
          ? { subscribedEventTypes: input.subscribedEventTypes }
          : {}),
        ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
      },
    });
    return this.toSummary(row);
  }

  /** Deletes the endpoint and its delivery history. Deliveries are removed first (rather than relying on an `ON DELETE CASCADE`) so this stays an explicit, auditable two-step operation matching this schema's general preference for restrictive FKs elsewhere. */
  async delete(tenantClient: TenantPrismaClient, id: string): Promise<void> {
    const existing = await tenantClient.webhookEndpoint.findUnique({
      where: { id },
    });
    if (!existing) throw new WebhookEndpointNotFoundError(id);

    await tenantClient.$transaction([
      tenantClient.webhookDelivery.deleteMany({
        where: { webhookEndpointId: id },
      }),
      tenantClient.webhookEndpoint.delete({ where: { id } }),
    ]);
  }

  async listDeliveries(
    tenantClient: TenantPrismaClient,
    webhookEndpointId: string,
  ) {
    const existing = await tenantClient.webhookEndpoint.findUnique({
      where: { id: webhookEndpointId },
    });
    if (!existing) throw new WebhookEndpointNotFoundError(webhookEndpointId);

    return tenantClient.webhookDelivery.findMany({
      where: { webhookEndpointId },
      orderBy: { createdAt: 'desc' },
    });
  }

  private toSummary(row: {
    id: string;
    url: string;
    subscribedEventTypes: string[];
    enabled: boolean;
    createdBy: string;
    createdAt: Date;
    updatedAt: Date;
  }): WebhookEndpointSummary {
    return {
      id: row.id,
      url: row.url,
      subscribedEventTypes: row.subscribedEventTypes,
      enabled: row.enabled,
      createdBy: row.createdBy,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }
}
