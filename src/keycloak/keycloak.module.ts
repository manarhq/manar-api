import { Global, Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { KeycloakAdminClient } from './keycloak-admin.client';
import { TenantProvisioningService } from './tenant-provisioning.service';

/**
 * Wires up the Keycloak Admin API client and the tenant provisioning
 * orchestrator that uses it. Global for the same reason `DatabaseModule`
 * is (see its doc comment): cross-cutting infrastructure every future
 * domain module may depend on, not just the CLI.
 *
 * Through Phase 13, this module was imported only by the CLI's own
 * `CliModule` and by tests that provision tenant fixtures directly
 * (`Test.createTestingModule({ imports: [AppModule, KeycloakModule] })`)
 * — the running HTTP app (`AppModule`) never provisioned tenants, so it
 * had no legitimate runtime need for `KeycloakAdminClient`/
 * `TenantProvisioningService` at all. Phase 14 changes that: `UsersService`
 * (`POST`/`DELETE /users/:id/role-bindings`) calls
 * `KeycloakAdminClient.assignRealmRole`/`removeRealmRole` at request time
 * to keep a Manar-side role grant/revoke in sync with Keycloak, the
 * role-assignment source of truth (`docs/human-auth.md`). `AppModule` now
 * imports this module directly for that reason — `TenantProvisioningService`
 * itself remains CLI-only in practice (nothing in the running HTTP app
 * calls it), but `KeycloakAdminClient` no longer is. Neither provider does
 * any eager I/O at construction/`onModuleInit` time, so importing this
 * module adds no new connection at boot — Keycloak Admin API calls only
 * ever happen lazily, when a method that needs one is actually invoked.
 */
@Global()
@Module({
  imports: [DatabaseModule],
  providers: [KeycloakAdminClient, TenantProvisioningService],
  exports: [KeycloakAdminClient, TenantProvisioningService],
})
export class KeycloakModule {}
