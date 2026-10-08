import { Module } from '@nestjs/common';
import { ReadinessService } from '../health/readiness.service';
import { FleetHeartbeatService } from './fleet-heartbeat.service';

/** Imported by AppModule (sender) and CliModule (fleet:keygen, fleet:report). */
@Module({
  providers: [ReadinessService, FleetHeartbeatService],
  exports: [FleetHeartbeatService],
})
export class FleetHeartbeatModule {}
