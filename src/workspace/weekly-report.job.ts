import {
  Injectable,
  Logger,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { ReportCardService } from './report-card.service';

const WEEK_MS = 7 * 86_400_000;
const CONCURRENCY = 8;

/** Next Sunday 18:00 UTC (22:00 in the UAE) strictly after `now`. */
export function nextSundayNight(now: Date): Date {
  const d = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 18),
  );
  d.setUTCDate(d.getUTCDate() + ((7 - d.getUTCDay()) % 7));
  return d.getTime() > now.getTime() ? d : new Date(d.getTime() + WEEK_MS);
}

/**
 * Worker-side timer: every Sunday night computes the card of every ACTIVE workspace, 8 at a
 * time, continuing past a failed tenant. Idempotent (one row per tenant and day), so a second
 * worker replica only repeats work. Off with REPORT_CARD_WEEKLY_JOB=false.
 */
@Injectable()
export class WeeklyReportJob
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(WeeklyReportJob.name);
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly cards: ReportCardService,
  ) {}

  onApplicationBootstrap(): void {
    if (process.env.REPORT_CARD_WEEKLY_JOB === 'false') return;
    this.schedule();
  }

  onApplicationShutdown(): void {
    clearTimeout(this.timer);
  }

  private schedule(): void {
    const wait = nextSundayNight(new Date()).getTime() - Date.now();
    this.timer = setTimeout(() => {
      void this.runAll().finally(() => this.schedule());
    }, wait);
    this.timer.unref();
  }

  async runAll(): Promise<{ ok: number; failed: number }> {
    const tenants = await this.control.tenant.findMany({
      where: { status: 'ACTIVE' },
      select: { id: true },
    });
    let ok = 0;
    let failed = 0;
    for (let i = 0; i < tenants.length; i += CONCURRENCY) {
      await Promise.all(
        tenants.slice(i, i + CONCURRENCY).map(async ({ id }) => {
          try {
            await this.cards.refresh(id);
            ok++;
          } catch (e) {
            failed++;
            this.logger.warn(
              `Report card failed for tenant ${id}: ${e instanceof Error ? e.message : String(e)}`,
            );
          }
        }),
      );
    }
    this.logger.log(`Weekly report cards: ${ok} computed, ${failed} failed`);
    return { ok, failed };
  }
}
