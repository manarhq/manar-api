import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { AiDefaultService } from '../../tenant-settings/ai-default.service';

/**
 * `node dist/cli.js ai:default-on [--dry-run]`: one-off, idempotent. Switches AI on for existing
 * non-Government, non-air-gapped workspaces still at the old default, keeping every owner's own
 * choice (read from each workspace's audit log), and records the choice on the tenant row.
 * `--dry-run` only reads (read-only transactions) and prints counts, never identifiers.
 */
@Command({
  name: 'ai:default-on',
  description:
    'Turn AI on for existing workspaces at the old default; keep owners’ own choices',
})
export class AiDefaultOnCommand extends CommandRunner {
  private readonly logger = new Logger(AiDefaultOnCommand.name);

  constructor(private readonly service: AiDefaultService) {
    super();
  }

  @Option({
    flags: '--dry-run',
    description: 'Read only: print the counts and change nothing',
  })
  parseDryRun(): boolean {
    return true;
  }

  @Option({
    flags: '--include-enterprise',
    description:
      'Live run: also flip company (enterprise) workspaces. Without it they are only counted',
  })
  parseIncludeEnterprise(): boolean {
    return true;
  }

  async run(
    _params: string[],
    options?: { dryRun?: boolean; includeEnterprise?: boolean },
  ): Promise<void> {
    const dryRun = options?.dryRun === true;
    const counts = await this.service.run({
      dryRun,
      includeEnterprise: options?.includeEnterprise === true,
    });
    this.logger.log(
      `${dryRun ? 'DRY RUN, nothing changed' : 'Applied'}: ${JSON.stringify(counts)}`,
    );
    process.exitCode = counts.failed > 0 || counts.completionFailed > 0 ? 1 : 0;
  }
}
