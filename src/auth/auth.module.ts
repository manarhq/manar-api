import { Global, Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { IdentityGuard } from './identity.guard';
import { MembershipService } from './membership.service';
import { TokenVerifierService } from './token-verifier.service';
import { JwksCacheService } from './jwks-cache.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { KnownIssuerRegistry } from './known-issuer-registry.service';
import { RolesGuard } from './roles.guard';
import { AccountsService } from '../staff/index/accounts.service';
import { DeviceIndexService } from '../staff/index/device-index.service';
import { RestrictionEnforcementModule } from '../staff/restrictions/restriction-enforcement.module';

/**
 * Wires up dynamic per-issuer JWT validation (`JwtAuthGuard`) and coarse
 * role-based endpoint protection (`RolesGuard`). Global for the same
 * reason `DatabaseModule` is — every future HTTP-facing domain module
 * will apply these guards. Deliberately not imported by `CliModule`: the
 * CLI has no HTTP requests to guard.
 */
@Global()
@Module({
  imports: [DatabaseModule, RestrictionEnforcementModule],
  providers: [
    // DESK indexes, written from token verification and device registration (global for both).
    AccountsService,
    DeviceIndexService,
    KnownIssuerRegistry,
    JwksCacheService,
    TokenVerifierService,
    MembershipService,
    JwtAuthGuard,
    IdentityGuard,
    RolesGuard,
  ],
  exports: [
    AccountsService,
    DeviceIndexService,
    KnownIssuerRegistry,
    JwksCacheService,
    TokenVerifierService,
    MembershipService,
    JwtAuthGuard,
    IdentityGuard,
    RolesGuard,
  ],
})
export class AuthModule {}
