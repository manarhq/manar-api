import { Module } from '@nestjs/common';
import { HealthController } from './health.controller';
import { ReadinessService } from './readiness.service';

/**
 * The kubelet-facing health surface. `ReadinessService` reaches its
 * dependencies through `ConfigService` (for the addresses it probes over
 * TCP) plus `ControlPrismaService`/`TenantDatabaseManager`, both of which
 * come from the `@Global()` `DatabaseModule` — so this module needs no
 * `imports` of its own, and, importantly, no import of the modules whose
 * dependencies it reports on.
 *
 * That last point is deliberate rather than incidental: a health module
 * that imported every infrastructure module it checks would make the
 * *ability to report an outage* depend on those same modules
 * instantiating cleanly, which is exactly backwards. See
 * `tcp-reachability.ts` for why the optional dependencies are probed by
 * address rather than through their clients.
 */
@Module({
  controllers: [HealthController],
  providers: [ReadinessService],
})
export class HealthModule {}
