import { Injectable, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { AuthCache } from '../database/auth-cache.service';
import { ControlPrismaService } from '../database/control-prisma.service';

/** An issuer this API accepts human tokens from. `boundTenant` is set only for a legacy per-tenant realm. */
export interface TrustedIssuer {
  issuerUrl: string;
  boundTenant?: { id: string; slug: string };
}

export interface KnownIssuer {
  tenantId: string;
  tenantSlug: string;
  issuerUrl: string;
}

/**
 * The allow-list gate `JwtAuthGuard` must pass before it will ever fetch a
 * JWKS document. A JWT's `iss` claim is attacker-controlled input until
 * it's been checked against something this deployment actually
 * provisioned — never resolved into a fetchable URL directly from the
 * token itself (that would let any caller point the guard at an arbitrary
 * URL of their choosing). This resolves an issuer string against the
 * control DB's `Tenant.keycloakIssuerUrl` column instead, which is only
 * ever written by `TenantProvisioningService` at provisioning time.
 */
@Injectable()
export class KnownIssuerRegistry {
  private readonly configured: Set<string>;

  constructor(
    private readonly control: ControlPrismaService,
    configService: ConfigService<AppConfig, true>,
    @Optional() private readonly cache?: AuthCache,
  ) {
    this.configured = new Set(
      (configService.get('AUTH_ISSUERS', { infer: true }) ?? '')
        .split(',')
        .map((i) => i.trim().replace(/\/+$/, ''))
        .filter(Boolean),
    );
  }

  /**
   * Human-token trust (JwtAuthGuard, throttler): an issuer from `AUTH_ISSUERS` (shared hosted
   * realm, a customer-hosted install's realm) or a legacy per-tenant realm provisioned by this
   * deployment. A configured issuer is never tenant-bound: its users reach a tenant only through
   * a Membership. A legacy per-tenant realm is bound to its tenant whatever its status; the
   * Membership lookup then fails closed for a tenant that is not ACTIVE.
   */
  async resolveTrusted(issuer: string): Promise<TrustedIssuer | null> {
    const normalized = issuer.replace(/\/+$/, '');
    if (this.configured.has(normalized)) return { issuerUrl: normalized };
    const load = async (): Promise<TrustedIssuer | null> => {
      const tenant = await this.control.tenant.findUnique({
        where: { keycloakIssuerUrl: issuer },
        select: { id: true, slug: true, keycloakIssuerUrl: true },
      });
      if (!tenant?.keycloakIssuerUrl) return null;
      return {
        issuerUrl: tenant.keycloakIssuerUrl,
        boundTenant: { id: tenant.id, slug: tenant.slug },
      };
    };
    return this.cache ? this.cache.remember(`i\n${issuer}`, load) : load();
  }

  async resolveByIssuer(issuer: string): Promise<KnownIssuer | null> {
    const tenant = await this.control.tenant.findUnique({
      where: { keycloakIssuerUrl: issuer },
    });

    if (!tenant || tenant.status !== 'ACTIVE' || !tenant.keycloakIssuerUrl) {
      return null;
    }

    return {
      tenantId: tenant.id,
      tenantSlug: tenant.slug,
      issuerUrl: tenant.keycloakIssuerUrl,
    };
  }
}
