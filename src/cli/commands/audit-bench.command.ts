import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { Inject, Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { Client as PgClient } from 'pg';
import { AuditService } from '../../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../../audit/audit-event-types';
import { AuditCheckpointService } from '../../audit/checkpoint/audit-checkpoint.service';
import {
  CHECKPOINT_PUBLIC_KEYS,
  type CheckpointKeyLookup,
} from '../../audit/checkpoint/checkpoint-format';
import type { KafkaPublisherService } from '../../audit/kafka-publisher.service';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';

interface AuditBenchOptions {
  seconds: number;
  concurrency: number;
  agents: number;
}

/**
 * `pnpm manar audit:bench [--seconds 60] [--concurrency 200] [--agents 500]`:
 * audit write throughput on this SITE's own database and OpenBao. Creates a
 * throwaway tenant, runs `concurrency` loops of `AuditService.record` for
 * `seconds` while sealing that tenant every second (as the worker does),
 * verifies its whole log, prints one JSON line, then removes the tenant.
 * Never touches other tenants. Kafka is left out (audit never awaits it).
 */
@Command({
  name: 'audit:bench',
  description: 'Measure audit write throughput on a throwaway tenant',
})
export class AuditBenchCommand extends CommandRunner {
  private readonly logger = new Logger(AuditBenchCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly checkpoints: AuditCheckpointService,
    @Inject(CHECKPOINT_PUBLIC_KEYS)
    private readonly checkpointKeys: CheckpointKeyLookup,
  ) {
    super();
  }

  async run(_params: string[], options: AuditBenchOptions): Promise<void> {
    const { seconds = 60, concurrency = 200, agents = 500 } = options;
    const audit = new AuditService(
      { publish: () => Promise.resolve() } as unknown as KafkaPublisherService,
      this.checkpointKeys,
    );
    const tenant = await this.tenants.provisionTenant({
      slug: `bench-${randomUUID().slice(0, 8)}`,
      name: 'Audit throughput benchmark',
    });
    const databaseName = tenant.databaseBinding!.databaseName;
    let sealing: NodeJS.Timeout | undefined;
    try {
      const client = await this.tenants.getClient(tenant.id);
      let sealRunning = false;
      sealing = setInterval(() => {
        if (sealRunning) return;
        sealRunning = true;
        void this.checkpoints
          .createCheckpoint(client, tenant.id)
          .catch((error: unknown) => this.logger.error(String(error)))
          .finally(() => (sealRunning = false));
      }, 1000);

      const latencies: number[] = [];
      const deadline = Date.now() + seconds * 1000;
      const started = performance.now();
      await Promise.all(
        Array.from({ length: concurrency }, async (_, worker) => {
          for (let i = 0; Date.now() < deadline; i += 1) {
            const t0 = performance.now();
            await audit.record(client, tenant.id, {
              eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
              actor: {
                type: 'agent',
                id: `bench-agent-${(worker * 7919 + i) % agents}`,
              },
              data: { worker, i },
            });
            latencies.push(performance.now() - t0);
          }
        }),
      );
      const elapsedS = (performance.now() - started) / 1000;
      clearInterval(sealing);
      sealing = undefined;
      await audit.onModuleDestroy();
      await this.checkpoints.createCheckpoint(client, tenant.id);

      const sorted = [...latencies].sort((a, b) => a - b);
      const at = (p: number) =>
        Number(
          (
            sorted[
              Math.min(sorted.length - 1, Math.floor(sorted.length * p))
            ] ?? 0
          ).toFixed(1),
        );
      const verify = await audit.verifyAuditChain(client, tenant.id);
      console.log(
        JSON.stringify({
          eventsPerSecond: Math.round(latencies.length / elapsedS),
          p50Ms: at(0.5),
          p99Ms: at(0.99),
          totalEvents: latencies.length,
          checkpoints: await client.auditCheckpoint.count(),
          verifyValid: verify.valid,
          ...(verify.valid ? {} : { brokenAt: verify.brokenAt }),
          seconds,
          concurrency,
          agents,
        }),
      );
    } finally {
      if (sealing) clearInterval(sealing);
      await this.control.tenantDatabaseBinding.deleteMany({
        where: { tenantId: tenant.id },
      });
      await this.control.secretReference.deleteMany({
        where: { tenantId: tenant.id },
      });
      await this.control.tenant.deleteMany({ where: { id: tenant.id } });
      const admin = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await admin.connect();
      await admin.query(
        `DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`,
      );
      await admin.end();
    }
  }

  @Option({
    flags: '--seconds <n>',
    description: 'How long to write (default 60)',
  })
  parseSeconds(value: string): number {
    return Number(value);
  }

  @Option({
    flags: '--concurrency <n>',
    description: 'Parallel writers (default 200)',
  })
  parseConcurrency(value: string): number {
    return Number(value);
  }

  @Option({
    flags: '--agents <n>',
    description: 'Distinct agent ids (default 500)',
  })
  parseAgents(value: string): number {
    return Number(value);
  }
}
