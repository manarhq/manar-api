import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
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

/** `pnpm manar workspaces:retry [--tenant <id>]`: put FAILED workspaces back in the queue. */
@Command({
  name: 'workspaces:retry',
  description: 'Re-queue workspaces whose provisioning gave up',
})
export class WorkspacesRetryCommand extends CommandRunner {
  private readonly logger = new Logger(WorkspacesRetryCommand.name);

  constructor(private readonly provisioning: WorkspaceProvisioningService) {
    super();
  }

  async run(_p: string[], o: { tenant?: string }): Promise<void> {
    this.logger.log(
      `Re-queued ${await this.provisioning.retryFailed(o.tenant)} workspace(s)`,
    );
  }

  @Option({ flags: '-t, --tenant <id>', description: 'Only this tenant id' })
  parseTenant(v: string): string {
    return v;
  }
}
