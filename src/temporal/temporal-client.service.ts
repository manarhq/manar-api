import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Client, Connection } from '@temporalio/client';
import type { AppConfig } from '../config/env.validation';

/**
 * The one place in either Nest application (human-facing `AppModule`,
 * agent-facing `AgentMtlsAppModule`) that holds a `@temporalio/client`
 * connection — used to *start* `ApprovalWorkflow`
 * (`POST /agent/v1/tools/invoke`, on a `APPROVAL_REQUIRED` decision) and to
 * *signal* it (`POST /approvals/:id/decide`). Never runs a Worker itself —
 * that's `src/worker.main.ts`'s own separate process (Section 28: workflow
 * code, and the Activities it calls, never share an event loop with the
 * Fastify HTTP server). See docs/approvals.md.
 */
@Injectable()
export class TemporalClientService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TemporalClientService.name);
  private connection: Connection | undefined;
  private client: Client | undefined;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {}

  async onModuleInit(): Promise<void> {
    const address = this.configService.get('TEMPORAL_ADDRESS', {
      infer: true,
    });
    this.connection = await Connection.connect({ address });
    this.client = new Client({
      connection: this.connection,
      namespace: this.configService.get('TEMPORAL_NAMESPACE', {
        infer: true,
      }),
    });
    this.logger.log(`Connected to Temporal at "${address}"`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.connection?.close();
  }

  get workflow(): Client['workflow'] {
    if (!this.client) {
      throw new Error(
        'TemporalClientService used before onModuleInit connected — is TemporalModule wired into this application?',
      );
    }
    return this.client.workflow;
  }

  get taskQueue(): string {
    return this.configService.get('TEMPORAL_TASK_QUEUE', { infer: true });
  }
}
