import { Module } from '@nestjs/common';
import {
  CurrentWorkspaceController,
  WorkspacesController,
} from './workspaces.controller';
import {
  SampleDirectoryService,
  WorkspaceProvisioningService,
  WorkspaceQueueLoop,
} from './workspace-provisioning.service';
import { SAMPLE_DIRECTORY, WORKSPACE_PROVISIONING } from './workspace-ports';
import { WorkspacesService } from './workspaces.service';

/**
 * Hosted workspaces (spec 4.1, 4.2, 7a). `AuthModule`, `DatabaseModule` and `ConfigModule` are
 * global. HTTP listener only. The two tokens are the interfaces the features track (sample
 * workspace) consumes.
 */
@Module({
  controllers: [WorkspacesController, CurrentWorkspaceController],
  providers: [
    WorkspaceProvisioningService,
    WorkspaceQueueLoop,
    WorkspacesService,
    SampleDirectoryService,
    {
      provide: WORKSPACE_PROVISIONING,
      useExisting: WorkspaceProvisioningService,
    },
    { provide: SAMPLE_DIRECTORY, useExisting: SampleDirectoryService },
  ],
  exports: [
    WorkspaceProvisioningService,
    WORKSPACE_PROVISIONING,
    SAMPLE_DIRECTORY,
  ],
})
export class WorkspacesModule {}
