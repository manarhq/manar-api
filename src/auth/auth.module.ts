import { Global, Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { JwksCacheService } from './jwks-cache.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { KnownIssuerRegistry } from './known-issuer-registry.service';

/**
 * Wires up dynamic per-issuer JWT validation (`JwtAuthGuard`). Global for
 * the same reason `DatabaseModule` is — every future HTTP-facing domain
 * module will apply this guard. Deliberately not imported by `CliModule`:
 * the CLI has no HTTP requests to guard.
 */
@Global()
@Module({
  imports: [DatabaseModule],
  providers: [KnownIssuerRegistry, JwksCacheService, JwtAuthGuard],
  exports: [KnownIssuerRegistry, JwksCacheService, JwtAuthGuard],
})
export class AuthModule {}
