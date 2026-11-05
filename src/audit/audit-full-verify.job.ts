import {
  Injectable,
  Logger,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { AuditFullVerifyService } from './audit-full-verify.service';

/**
 * Worker-side: checks every hour (and at start) which tenants are due. The schedule lives in the
 * database: a tenant is due when its newest run started before the last 22:00 UTC (02:00 UAE), so
 * a worker restarted after 22:00 still runs tonight. Off with AUDIT_FULL_VERIFY_JOB=false.
 */
@Injectable()
export class AuditFullVerifyJob
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  static readonly TICK_MS = 3_600_000;
  private readonly logger = new Logger(AuditFullVerifyJob.name);
  private timer?: NodeJS.Timeout;
  private running = false;

  constructor(private readonly full: AuditFullVerifyService) {}

  onApplicationBootstrap(): void {
    if (process.env.AUDIT_FULL_VERIFY_JOB === 'false') return;
    void this.tick();
    this.timer = setInterval(
      () => void this.tick(),
      AuditFullVerifyJob.TICK_MS,
    );
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    clearInterval(this.timer);
  }

  async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const r = await this.full.runAll();
      if (r.checked > 0) {
        this.logger.log(
          `Full audit verification: ${r.checked} checked, ${r.failed} failed, ${r.errored} errored`,
        );
      }
    } catch (error) {
      this.logger.error(`Full audit verification tick: ${String(error)}`);
    } finally {
      this.running = false;
    }
  }
}
