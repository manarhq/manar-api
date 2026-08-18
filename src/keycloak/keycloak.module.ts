import { Global, Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { KeycloakAdminClient } from './keycloak-admin.client';
import { TenantProvisioningService } from './tenant-provisioning.service';

/**
 * Wires up the Keycloak Admin API client and the tenant provisioning
 * orchestrator that uses it. Global for the same reason `DatabaseModule`
 * is (see its doc comment): cross-cutting infrastructure every future
 * domain module may depend on, not just the CLI.
 */
@Global()
@Module({
  imports: [DatabaseModule],
  providers: [KeycloakAdminClient, TenantProvisioningService],
  exports: [KeycloakAdminClient, TenantProvisioningService],
})
export class KeycloakModule {}
