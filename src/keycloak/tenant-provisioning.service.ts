import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  ProvisionTenantInput,
  TenantDatabaseManager,
} from '../database/tenant-database-manager.service';
import { ROLES } from '../auth/roles';
import { KeycloakAdminClient } from './keycloak-admin.client';

/**
 * Orchestrates full tenant provisioning: the database half (Phase 2's
 * `TenantDatabaseManager.provisionTenant`, unchanged) plus the Keycloak
 * half added in Phase 3 — a realm, its eight application roles, and a
 * confidential client for manar-api to validate tokens against (see
 * docs/human-auth.md).
 *
 * This is the `TenantProvisioningService` the Phase 3 design spec asks for
 * ("extend the TenantProvisioningService introduced conceptually in
 * Phase 2, or introduce it now"). Phase 2 built provisioning directly into
 * `TenantDatabaseManager` rather than as a separate service; this class
 * wraps that method rather than duplicating it, adding the Keycloak leg
 * around it.
 */
@Injectable()
export class TenantProvisioningService {
  private readonly logger = new Logger(TenantProvisioningService.name);

  constructor(
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly keycloakAdminClient: KeycloakAdminClient,
    private readonly control: ControlPrismaService,
    private readonly configService: ConfigService<AppConfig, true>,
  ) {}

  /**
   * Provisions a tenant's database (Phase 2 behavior, unchanged) and then
   * its Keycloak realm/roles/client (Phase 3).
   *
   * **Known limitation** (documented, not silently swallowed — consistent
   * with `TenantDatabaseManager.provisionTenant`'s own "no automatic
   * rollback" stance, see docs/tenant-isolation.md): the database leg
   * already transitions the tenant to `ACTIVE` before the Keycloak leg
   * runs. If the Keycloak leg fails, the tenant is left `ACTIVE` with a
   * provisioned, working database but no realm (`keycloakRealm` stays
   * null) — `JwtAuthGuard` can never resolve an issuer for it, so no human
   * can authenticate against it yet, but nothing else treats it as
   * partially provisioned. Restructuring `TenantDatabaseManager` to defer
   * `ACTIVE` until both legs succeed is out of scope for this phase, which
   * builds on top of the existing method rather than changing its
   * contract; a retry path for the Keycloak leg alone is future
   * admin-tooling work.
   */
  async provisionTenant(input: ProvisionTenantInput) {
    const tenant = await this.tenantDatabaseManager.provisionTenant(input);

    const clientId = this.configService.get('KEYCLOAK_CLIENT_ID', {
      infer: true,
    });
    const realmName = tenant.slug;

    try {
      await this.keycloakAdminClient.createRealm(realmName);

      for (const role of ROLES) {
        await this.keycloakAdminClient.createRealmRole(realmName, role);
      }

      const clientSecret =
        await this.keycloakAdminClient.createConfidentialClient(
          realmName,
          clientId,
        );

      const issuerUrl = this.keycloakAdminClient.issuerUrlForRealm(realmName);

      await this.control.$transaction([
        this.control.tenant.update({
          where: { id: tenant.id },
          data: {
            keycloakRealm: realmName,
            keycloakIssuerUrl: issuerUrl,
            keycloakClientId: clientId,
          },
        }),
        this.control.secretReference.create({
          data: {
            tenantId: tenant.id,
            kind: 'KEYCLOAK_CLIENT_SECRET',
            provider: 'CONTROL_DB',
            // See prisma/control.prisma's SecretProvider enum doc: CONTROL_DB
            // stores the value directly (no env-var indirection is possible
            // for a secret that's generated per tenant, at provisioning
            // time). Never logged.
            reference: clientSecret,
          },
        }),
      ]);
    } catch (error) {
      this.logger.error(
        `Keycloak provisioning failed for tenant "${input.slug}" (id=${tenant.id}) after its database was already provisioned; tenant is ACTIVE but has no usable realm — see TenantProvisioningService's known limitations`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    }

    return this.control.tenant.findUniqueOrThrow({
      where: { id: tenant.id },
      include: { databaseBinding: true },
    });
  }
}
