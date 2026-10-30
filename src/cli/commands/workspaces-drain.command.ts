import { Logger } from '@nestjs/common';
import { Command, CommandRunner } from 'nest-commander';
import { WorkspaceProvisioningService } from '../../workspaces/workspace-provisioning.service';

/** `pnpm manar workspaces:drain`: provision queued workspaces now (the API also does this on a timer). */
@Command({
  name: 'workspaces:drain',
  description: 'Provision queued workspaces',
})
export class WorkspacesDrainCommand extends CommandRunner {
  private readonly logger = new Logger(WorkspacesDrainCommand.name);

  constructor(private readonly provisioning: WorkspaceProvisioningService) {
    super();
  }

  async run(): Promise<void> {
    this.logger.log(
      `Provisioned ${await this.provisioning.drainQueue()} queued workspace(s)`,
    );
  }
}
