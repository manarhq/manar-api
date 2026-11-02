import { Module } from '@nestjs/common';
import { GrowthAuditService } from '../growth/growth-audit.service';
import {
  DataCollectionController,
  WorkspaceDataPreferencesController,
} from './data-collection.controller';
import { DataCollectionService } from './data-collection.service';
import { PostHogClient } from './posthog.client';

/** Services only: shared by the HTTP app, the mTLS app (device config and telemetry) and the worker. */
@Module({
  providers: [DataCollectionService, PostHogClient, GrowthAuditService],
  exports: [DataCollectionService],
})
export class DataCollectionModule {}

/** Human HTTP routes. */
@Module({
  imports: [DataCollectionModule],
  controllers: [DataCollectionController, WorkspaceDataPreferencesController],
})
export class DataCollectionHttpModule {}
