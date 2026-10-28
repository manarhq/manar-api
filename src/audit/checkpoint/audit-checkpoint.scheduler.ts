import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { AuditCheckpointService } from './audit-checkpoint.service';

/**
 * Seals every ACTIVE tenant's audit log once a second (worker process only).
 * The next round starts a second after the previous one ends, so a slow round
 * never overlaps the next; one tenant's failure (OpenBao down, a dropped
 * database) is logged and the others still get sealed. Several worker
 * replicas are safe: `createCheckpoint` lets one writer per tenant through.
 */
@Injectable()
export class AuditCheckpointScheduler implements OnModuleInit, OnModuleDestroy {
  static readonly INTERVAL_MS = 1000;

  private readonly logger = new Logger(AuditCheckpointScheduler.name);
  private timer: NodeJS.Timeout | null = null;
  private stopped = false;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly checkpoints: AuditCheckpointService,
  ) {}

  onModuleInit(): void {
    this.stopped = false;
    this.schedule();
  }

  onModuleDestroy(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private schedule(): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      void this.round().finally(() => this.schedule());
    }, AuditCheckpointScheduler.INTERVAL_MS);
  }

  private async round(): Promise<void> {
    let tenantIds: string[];
    try {
      tenantIds = (
        await this.control.tenant.findMany({
          where: { status: 'ACTIVE' },
          select: { id: true },
        })
      ).map((t) => t.id);
    } catch (error) {
      this.logger.error(`Audit checkpoint round skipped: ${String(error)}`);
      return;
    }
    for (const id of tenantIds) {
      if (this.stopped) return;
      try {
        const client = await this.tenants.getClient(id);
        await this.checkpoints.createCheckpoint(client, id);
      } catch (error) {
        this.logger.error(
          `Audit checkpoint failed for tenant "${id}": ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }
}
