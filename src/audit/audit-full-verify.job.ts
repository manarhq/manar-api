import {
  Injectable,
  Logger,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { AuditFullVerifyService } from './audit-full-verify.service';

/** Next 22:00 UTC (02:00 in the UAE) strictly after `now`. */
export function nextFullVerifyAt(now: Date): Date {
  const d = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 22),
  );
  return d.getTime() > now.getTime() ? d : new Date(d.getTime() + 86_400_000);
}

/** Worker-side nightly timer. Off with AUDIT_FULL_VERIFY_JOB=false. */
@Injectable()
export class AuditFullVerifyJob
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(AuditFullVerifyJob.name);
  private timer?: NodeJS.Timeout;

  constructor(private readonly full: AuditFullVerifyService) {}

  onApplicationBootstrap(): void {
    if (process.env.AUDIT_FULL_VERIFY_JOB === 'false') return;
    this.schedule();
  }

  onApplicationShutdown(): void {
    clearTimeout(this.timer);
  }

  private schedule(): void {
    const wait = nextFullVerifyAt(new Date()).getTime() - Date.now();
    this.timer = setTimeout(() => {
      void this.full
        .runAll()
        .then((r) =>
          this.logger.log(
            `Nightly full audit verification: ${r.checked} checked, ${r.failed} failed`,
          ),
        )
        .catch((e) =>
          this.logger.error(`Nightly full audit verification: ${String(e)}`),
        )
        .finally(() => this.schedule());
    }, wait);
    this.timer.unref();
  }
}
