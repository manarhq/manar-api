import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { ReadinessService } from '../health/readiness.service';
import { PlatformOpsService } from '../platform/platform-ops.service';
import { FleetHeartbeatService } from './fleet-heartbeat.service';

/** Imported by AppModule (sender) and CliModule (fleet:keygen, fleet:report). AuditModule is
 * imported here for the CLI, where it is not otherwise loaded (audit chain status). */
@Module({
  imports: [AuditModule],
  providers: [ReadinessService, PlatformOpsService, FleetHeartbeatService],
  exports: [FleetHeartbeatService],
})
export class FleetHeartbeatModule {}
