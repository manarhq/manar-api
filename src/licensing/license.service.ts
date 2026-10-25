import type { KeyObject } from 'node:crypto';
import { unwatchFile, watchFile } from 'node:fs';
import { readFile } from 'node:fs/promises';
import {
  Inject,
  Injectable,
  Logger,
  Optional,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { recordLicense } from '../metrics/metrics';
import {
  LICENSE_STATUSES,
  TRUST_ANCHOR_DIR,
  evaluate,
  loadTrustAnchors,
  verifyLicense,
  type LicenseStatus,
  type Usage,
  type Verification,
} from './license';

const HOUR = 3_600_000;

/** Overrides the trust anchor directory; tests only. */
export const LICENSE_KEY_DIR = Symbol('LICENSE_KEY_DIR');

/**
 * Holds the deployment's licence status (docs/licensing.md). Re-checks at boot, every hour and
 * when the licence file changes. Soft limits only: nothing reads this on a request path to allow
 * or deny, and no failure here throws; a bad or missing licence is a status, a warning log and a
 * metric.
 */
@Injectable()
export class LicenseService
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(LicenseService.name);
  private readonly keys: Map<string, KeyObject>;
  private current?: LicenseStatus;
  private inFlight?: Promise<LicenseStatus>;
  private timer?: NodeJS.Timeout;
  private watched?: string;

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    @Optional() @Inject(LICENSE_KEY_DIR) keyDir?: string,
  ) {
    const { keys, skipped } = loadTrustAnchors(keyDir ?? TRUST_ANCHOR_DIR);
    for (const file of skipped)
      this.logger.warn(
        `Licence trust anchor ${file} skipped: not an Ed25519 public key`,
      );
    this.keys = keys;
  }

  onApplicationBootstrap(): void {
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), HOUR);
    this.timer.unref();
    const file = this.config.get('MANAR_LICENSE_FILE', { infer: true });
    if (file) {
      // Polls the file's stat once a minute; a Secret mount's symlink swap shows up as a change.
      watchFile(
        file,
        { interval: 60_000, persistent: false },
        () => void this.refresh(),
      );
      this.watched = file;
    }
  }

  onApplicationShutdown(): void {
    if (this.timer) clearInterval(this.timer);
    if (this.watched) unwatchFile(this.watched);
  }

  /** The last computed status; computes one if none exists yet. */
  async status(): Promise<LicenseStatus> {
    return this.current ?? this.refresh();
  }

  refresh(): Promise<LicenseStatus> {
    this.inFlight ??= this.compute().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  private async compute(): Promise<LicenseStatus> {
    const [{ verification, unreadable }, usage] = await Promise.all([
      this.read(),
      this.usage(),
    ]);
    const s = evaluate(
      verification,
      usage,
      new Date(),
      this.config.get('MANAR_DEPLOYMENT', { infer: true }),
    );
    if (unreadable) s.reason = 'file_unreadable';
    recordLicense(s.status, LICENSE_STATUSES, s.expiresAt, s.limits, s.usage);
    this.logChange(this.current, s);
    this.current = s;
    return s;
  }

  private async read(): Promise<{
    verification: Verification;
    unreadable: boolean;
  }> {
    const file = this.config.get('MANAR_LICENSE_FILE', { infer: true });
    let token = this.config.get('MANAR_LICENSE', { infer: true });
    if (file) {
      try {
        token = await readFile(file, 'utf8');
      } catch {
        return { verification: { result: 'missing' }, unreadable: true };
      }
    }
    return { verification: verifyLicense(token, this.keys), unreadable: false };
  }

  /**
   * Usage the limits are compared with: ACTIVE tenants in the control database, and ACTIVE
   * (enrolled, not revoked or killed) agents summed over those tenants' databases. The same
   * sources as the fleet heartbeat's counts. A tenant database that cannot be reached is
   * skipped, so the agent count can only be low, never high; if the control database cannot be
   * read, usage is unknown and no limit is reported as exceeded.
   */
  private async usage(): Promise<Usage> {
    try {
      const rows = await this.control.tenant.findMany({
        where: { status: 'ACTIVE' },
        select: { id: true },
      });
      let agents = 0;
      for (const { id } of rows) {
        try {
          const db = await this.tenants.getClient(id);
          agents += await db.agent.count({ where: { status: 'ACTIVE' } });
        } catch {
          // skipped, see above
        }
      }
      return { agents, tenants: rows.length };
    } catch {
      return { agents: null, tenants: null };
    }
  }

  /** One structured line per status change: ids, dates and counts only, never the licence. */
  private logChange(prev: LicenseStatus | undefined, s: LicenseStatus): void {
    if (prev?.status === s.status && prev.reason === s.reason) return;
    const entry = {
      message: `Licence status ${s.status}`,
      event: 'license_status_changed',
      status: s.status,
      previous: prev?.status ?? null,
      reason: s.reason,
      licenseId: s.licenseId,
      kid: s.kid,
      deployment: s.deployment,
      expiresAt: s.expiresAt,
      daysLeft: s.daysLeft,
      limits: s.limits,
      usage: s.usage,
      overLimit: s.overLimit,
    };
    if (s.status === 'valid') this.logger.log(entry);
    else this.logger.warn(entry);
  }
}
