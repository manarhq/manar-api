import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { isExternalAiProvider } from '../ai-advisory/ai-advisory.config';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { UpdateTenantSettingsRequest } from './tenant-settings.validation';

export interface TenantSettings {
  tenantId: string;
  slug: string;
  name: string;
  residency: string;
  allowExternalAi: boolean;
  allowOutboundTelemetry: boolean;
  allowCloudStorage: boolean;
  approvalsAdminsOnly: boolean;
  updatedAt: Date;
  sso: {
    realm: string;
    issuerUrl: string;
    clientId: string;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    endSessionEndpoint: string;
    jwksUri: string;
  } | null;
  aiProvider: {
    provider: 'anthropic' | 'ollama' | 'vllm';
    isExternal: boolean;
  };
  rateLimit: {
    humanRequestLimit: number;
    humanWindowMs: number;
  };
}

/**
 * Phase 14 (Users/Roles/Settings) — `GET`/`PATCH /tenant/settings`, the
 * backing service for `manar-web`'s `/settings/security`, `/settings/sso`,
 * `/settings/residency`, and `/settings/ai` pages. The caller's own tenant
 * only (`auth.tenant.id`, never a tenant id accepted from the request —
 * Section 23's standing rule); there is no cross-tenant view here at all.
 *
 * Four fields are genuinely writable (`residency`/`allowExternalAi`/
 * `allowOutboundTelemetry`/`allowCloudStorage` — the `Tenant` columns
 * Phase 2 added). Everything else this returns is read-only, surfaced
 * because it's genuinely useful to show alongside those four, not because
 * it's tenant-settings state itself:
 *
 *   - `sso` mirrors Phase 11b's `GET /tenants/:slug/oidc-config` (public,
 *     unauthenticated there because it runs pre-login; this is the same
 *     data for an already-authenticated caller, for the `/settings/sso`
 *     page's read-only display). SSO federation configuration itself
 *     lives entirely in Keycloak's own admin console — this page links
 *     out rather than duplicating it, per this phase's design spec.
 *   - `aiProvider` reflects `AI_ADVISORY_PROVIDER` — deployment-wide
 *     `manar-api`-side config (see `AiAdvisoryConfigSchema`'s doc comment
 *     for why `manar-api` has no way to ask `manar-ai` this over gRPC),
 *     never per-tenant, so it's read-only here regardless of caller role.
 *   - `rateLimit` reflects `RATE_LIMIT_HUMAN_LIMIT`/`_TTL_MS`
 *     (`src/rate-limit/rate-limit.config.ts`) — also deployment-wide, not
 *     per-tenant-adjustable (no per-tenant override exists anywhere in
 *     this codebase's rate-limit machinery), so it's informational only.
 */
@Injectable()
export class TenantSettingsService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly auditService: AuditService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  async getSettings(tenantId: string): Promise<TenantSettings> {
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
    });
    if (!tenant) {
      // Can't actually happen for an authenticated caller (JwtAuthGuard
      // already resolved this exact tenantId from a verified token's
      // issuer) -- defensive only, matching this codebase's fail-loud
      // posture rather than assuming the impossible never happens.
      throw new NotFoundException(`Tenant "${tenantId}" was not found`);
    }
    return this.toSettings(tenant);
  }

  /**
   * `PATCH /tenant/settings`. Writes directly to the control DB's
   * `Tenant` row — `AiAdvisoryClient.residencyAllows` (Phase 12a) reads
   * this exact row live, with no cache, on every AI-advisory-eligible
   * call, so a change here is effective on the very next such request,
   * not just "eventually" (verified by
   * `test/tenant-settings.e2e-spec.ts`'s residency-enforcement scenario —
   * see that file for why this isn't just assumed).
   */
  async updateSettings(
    tenantId: string,
    updatedByUserId: string,
    input: UpdateTenantSettingsRequest,
  ): Promise<TenantSettings> {
    if (input.approvalsAdminsOnly !== undefined) {
      const current = await this.control.tenant.findUnique({
        where: { id: tenantId },
        select: { kind: true },
      });
      if (current?.kind !== 'COMPANY')
        throw new BadRequestException(
          '"Admins only" approvals are for company workspaces. Nothing was changed.',
        );
    }
    const tenant = await this.control.tenant.update({
      where: { id: tenantId },
      data: {
        ...(input.residency !== undefined
          ? { residency: input.residency }
          : {}),
        ...(input.allowExternalAi !== undefined
          ? { allowExternalAi: input.allowExternalAi }
          : {}),
        ...(input.allowOutboundTelemetry !== undefined
          ? { allowOutboundTelemetry: input.allowOutboundTelemetry }
          : {}),
        ...(input.allowCloudStorage !== undefined
          ? { allowCloudStorage: input.allowCloudStorage }
          : {}),
        ...(input.approvalsAdminsOnly !== undefined
          ? { approvalsAdminsOnly: input.approvalsAdminsOnly }
          : {}),
      },
    });

    // The audit chain itself lives in the tenant's own isolated database
    // (Phase 9a), even though the row just written lives in the control
    // DB -- same convention every other retrofit point in this codebase
    // follows (see AUDIT_EVENT_TYPES's doc comment).
    await this.recordAuditEvent(tenantId, updatedByUserId, input);

    return this.toSettings(tenant);
  }

  private async recordAuditEvent(
    tenantId: string,
    updatedByUserId: string,
    input: UpdateTenantSettingsRequest,
  ): Promise<void> {
    const tenantClient = await this.tenantDatabaseManager.getClient(tenantId);
    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.TENANT_SETTINGS_UPDATED,
      actor: { type: 'human', id: updatedByUserId },
      data: { ...input },
    });
  }

  private toSettings(tenant: {
    id: string;
    slug: string;
    name: string;
    residency: string;
    allowExternalAi: boolean;
    allowOutboundTelemetry: boolean;
    allowCloudStorage: boolean;
    approvalsAdminsOnly: boolean;
    kind: string;
    updatedAt: Date;
    keycloakRealm: string | null;
    keycloakIssuerUrl: string | null;
    keycloakClientId: string | null;
  }): TenantSettings {
    const provider = this.configService.get('AI_ADVISORY_PROVIDER', {
      infer: true,
    });
    const rateLimitLimit = this.configService.get('RATE_LIMIT_HUMAN_LIMIT', {
      infer: true,
    });
    const rateLimitTtlMs = this.configService.get('RATE_LIMIT_HUMAN_TTL_MS', {
      infer: true,
    });

    const sso =
      tenant.keycloakRealm && tenant.keycloakIssuerUrl
        ? {
            realm: tenant.keycloakRealm,
            issuerUrl: tenant.keycloakIssuerUrl,
            clientId: tenant.keycloakClientId ?? '',
            authorizationEndpoint: `${tenant.keycloakIssuerUrl}/protocol/openid-connect/auth`,
            tokenEndpoint: `${tenant.keycloakIssuerUrl}/protocol/openid-connect/token`,
            endSessionEndpoint: `${tenant.keycloakIssuerUrl}/protocol/openid-connect/logout`,
            jwksUri: `${tenant.keycloakIssuerUrl}/protocol/openid-connect/certs`,
          }
        : null;

    return {
      tenantId: tenant.id,
      slug: tenant.slug,
      name: tenant.name,
      residency: tenant.residency,
      allowExternalAi: tenant.allowExternalAi,
      allowOutboundTelemetry: tenant.allowOutboundTelemetry,
      allowCloudStorage: tenant.allowCloudStorage,
      approvalsAdminsOnly:
        tenant.kind === 'COMPANY' && tenant.approvalsAdminsOnly,
      updatedAt: tenant.updatedAt,
      sso,
      aiProvider: { provider, isExternal: isExternalAiProvider(provider) },
      rateLimit: {
        humanRequestLimit: rateLimitLimit,
        humanWindowMs: rateLimitTtlMs,
      },
    };
  }
}
