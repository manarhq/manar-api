import { Module } from '@nestjs/common';
import {
  CurrentWorkspaceController,
  WorkspacesController,
} from './workspaces.controller';
import {
  WorkspaceProvisioningService,
  WorkspaceQueueLoop,
} from './workspace-provisioning.service';
import { WorkspacesService } from './workspaces.service';

/**
 * Hosted workspaces (spec 4.1, 4.2, 7a). `AuthModule`, `DatabaseModule` and `ConfigModule` are
 * global. HTTP listener only.
 */
@Module({
  controllers: [WorkspacesController, CurrentWorkspaceController],
  providers: [
    WorkspaceProvisioningService,
    WorkspaceQueueLoop,
    WorkspacesService,
  ],
  exports: [WorkspaceProvisioningService],
})
export class WorkspacesModule {}
