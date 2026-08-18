import { Injectable } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';

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
  constructor(private readonly control: ControlPrismaService) {}

  /**
   * Returns the matching tenant's identity + its *server-recorded* issuer
   * URL (not the caller-supplied string — they're identical by
   * construction of the `where` clause, but returning the DB value keeps
   * every downstream consumer using a value this deployment vouches for),
   * or `null` if `issuer` doesn't match any `ACTIVE` tenant's provisioned
   * realm. Never falls back to any default issuer.
   */
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
