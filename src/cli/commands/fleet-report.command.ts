import { writeFile } from 'node:fs/promises';
import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { FleetHeartbeatService } from '../../fleet-heartbeat/fleet-heartbeat.service';

/**
 * `pnpm manar fleet:report --out report.json`: writes one signed heartbeat envelope to a file,
 * for customer-hosted installs without outbound access. Upload it in the admin console
 * (manar-fleet POST /deployments/:id/reports). Needs FLEET_DEPLOYMENT_ID.
 */
@Command({
  name: 'fleet:report',
  description: 'Write a signed manar-fleet report file',
})
export class FleetReportCommand extends CommandRunner {
  private readonly logger = new Logger(FleetReportCommand.name);

  constructor(private readonly heartbeat: FleetHeartbeatService) {
    super();
  }

  async run(_: string[], options: { out: string }): Promise<void> {
    const envelope = await this.heartbeat.signedEnvelope();
    await writeFile(options.out, `${JSON.stringify(envelope)}\n`, {
      mode: 0o644,
    });
    this.logger.log(`Wrote signed report to ${options.out}`);
  }

  @Option({
    flags: '-o, --out <file>',
    description: 'Output file',
    required: true,
  })
  parseOut(value: string): string {
    return value;
  }
}
