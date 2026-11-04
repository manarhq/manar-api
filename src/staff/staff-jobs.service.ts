import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { StaffAuditService } from './audit/staff-audit.service';
import { StaffRbacService } from './rbac/staff-rbac.service';

const MINUTE = 60_000;

/**
 * Background work of the staff listener: sign the audit chain head every minute (spec §11.5),
 * close expired elevations (tidiness; their power already ended), reconcile RBAC every 5 minutes
 * and on boot (AC-29), purge error references after 30 days (AC-11). Each runs on every replica;
 * the work is idempotent and locked where it writes.
 */
@Injectable()
export class StaffJobsService
  implements OnApplicationBootstrap, OnModuleDestroy
{
  private readonly logger = new Logger(StaffJobsService.name);
  private readonly timers: NodeJS.Timeout[] = [];

  constructor(
    private readonly control: ControlPrismaService,
    private readonly audit: StaffAuditService,
    private readonly rbac: StaffRbacService,
  ) {}

  onApplicationBootstrap(): void {
    void this.run('rbac seed', () => this.rbac.ensureBuiltInRoles()).then(() =>
      this.run('rbac reconcile', () => this.rbac.reconcile({ dryRun: false })),
    );
    this.every(MINUTE, 'audit checkpoint', () => this.audit.checkpoint());
    this.every(MINUTE, 'close elevations', () =>
      this.rbac.closeExpiredElevations(),
    );
    this.every(5 * MINUTE, 'rbac reconcile', () =>
      this.rbac.reconcile({ dryRun: false }),
    );
    this.every(60 * MINUTE, 'purge error references', () =>
      this.control.staffErrorReference.deleteMany({
        where: { at: { lt: new Date(Date.now() - 30 * 24 * 60 * MINUTE) } },
      }),
    );
  }

  onModuleDestroy(): void {
    for (const t of this.timers) clearInterval(t);
  }

  private every(ms: number, name: string, fn: () => Promise<unknown>) {
    const t = setInterval(() => void this.run(name, fn), ms);
    t.unref();
    this.timers.push(t);
  }

  private async run(name: string, fn: () => Promise<unknown>): Promise<void> {
    try {
      await fn();
    } catch (error) {
      this.logger.error(`${name} failed: ${String(error)}`);
    }
  }
}
