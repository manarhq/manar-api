import {
  randomBytes,
  sign,
  createPrivateKey,
  type KeyObject,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
  Injectable,
  Logger,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ReadinessService } from '../health/readiness.service';
import { OpenBaoKvClient } from '../openbao/openbao-kv.client';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const VERSION = (require('../../package.json') as { version: string }).version;

const BackupFileSchema = z.object({
  status: z.enum(['ok', 'failed', 'running', 'unknown']),
  lastBackupAt: z.iso.datetime({ offset: true }).nullable().default(null),
  lastRestoreTestAt: z.iso.datetime({ offset: true }).nullable().default(null),
});

export interface HeartbeatPayload {
  v: 1;
  deploymentId: string;
  timestamp: string;
  nonce: string;
  version: string;
  gitSha: string;
  health: {
    status: 'ok' | 'degraded' | 'down';
    checks: Record<string, 'up' | 'down'>;
  };
  backup: z.infer<typeof BackupFileSchema>;
  counts: Record<string, number>;
}

export interface SignedEnvelope {
  payload: string;
  signature: string;
}

/**
 * Builds, signs and sends the manar-fleet heartbeat (ADR-0010). The payload is versions,
 * dependency health, backup status and counts only: no tenant names, no ids of tenants, no
 * PII. Signed with an Ed25519 key read from OpenBao; manar-fleet verifies it against the
 * registered public key and rejects replays by timestamp and nonce.
 */
@Injectable()
export class FleetHeartbeatService
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(FleetHeartbeatService.name);
  private timer?: NodeJS.Timeout;
  private key?: KeyObject;

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly readiness: ReadinessService,
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly kv: OpenBaoKvClient,
  ) {}

  onApplicationBootstrap(): void {
    const url = this.config.get('FLEET_HEARTBEAT_URL', { infer: true });
    if (!url) return;
    if (!this.config.get('FLEET_DEPLOYMENT_ID', { infer: true })) {
      this.logger.error(
        'FLEET_HEARTBEAT_URL is set but FLEET_DEPLOYMENT_ID is not; heartbeat off',
      );
      return;
    }
    const minutes = this.config.get('FLEET_HEARTBEAT_INTERVAL_MINUTES', {
      infer: true,
    });
    const tick = () => void this.send(url);
    setTimeout(tick, 5_000).unref();
    this.timer = setInterval(tick, minutes * 60_000);
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async send(url: string): Promise<boolean> {
    try {
      const envelope = await this.signedEnvelope();
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(envelope),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok)
        this.logger.warn(`Fleet heartbeat rejected: HTTP ${res.status}`);
      return res.ok;
    } catch (error) {
      this.logger.warn(
        `Fleet heartbeat failed: ${error instanceof Error ? error.name : 'error'}`,
      );
      return false;
    }
  }

  async signedEnvelope(): Promise<SignedEnvelope> {
    return signPayload(await this.payload(), await this.signingKey());
  }

  async payload(): Promise<HeartbeatPayload> {
    const report = await this.readiness.check();
    const checks: Record<string, 'up' | 'down'> = {};
    for (const [name, dep] of Object.entries(report.dependencies))
      checks[name] = dep.status === 'ok' ? 'up' : 'down';
    return {
      v: 1,
      deploymentId: this.config.get('FLEET_DEPLOYMENT_ID', { infer: true }),
      timestamp: new Date().toISOString(),
      nonce: randomBytes(16).toString('hex'),
      version: VERSION,
      gitSha: this.config.get('MANAR_GIT_SHA', { infer: true }) ?? 'unknown',
      health: {
        status: report.status === 'unhealthy' ? 'down' : report.status,
        checks,
      },
      backup: await this.backup(),
      counts: await this.counts(),
    };
  }

  private async backup(): Promise<HeartbeatPayload['backup']> {
    const file = this.config.get('FLEET_BACKUP_STATUS_FILE', { infer: true });
    const unknown = {
      status: 'unknown' as const,
      lastBackupAt: null,
      lastRestoreTestAt: null,
    };
    if (!file) return unknown;
    try {
      const parsed = BackupFileSchema.safeParse(
        JSON.parse(await readFile(file, 'utf8')),
      );
      return parsed.success ? parsed.data : unknown;
    } catch {
      return unknown;
    }
  }

  /** Counts only. A tenant whose database is unreachable is skipped, not reported. */
  private async counts(): Promise<Record<string, number>> {
    const rows = await this.control.tenant.findMany({
      where: { status: { not: 'DELETED' } },
      select: { id: true, status: true },
    });
    const active = rows.filter((t) => t.status === 'ACTIVE');
    let agents = 0;
    let agentsActive = 0;
    for (const t of active) {
      try {
        const db = await this.tenants.getClient(t.id);
        agents += await db.agent.count();
        agentsActive += await db.agent.count({ where: { status: 'ACTIVE' } });
      } catch {
        // counted under tenantsActive only
      }
    }
    return {
      tenants: rows.length,
      tenantsActive: active.length,
      agents,
      agentsActive,
    };
  }

  private async signingKey(): Promise<KeyObject> {
    if (this.key) return this.key;
    const path = this.config.get('FLEET_HEARTBEAT_KEY_PATH', { infer: true });
    const secret = await this.kv.readSecret(path);
    if (typeof secret.privateKeyPem !== 'string')
      throw new Error(
        'Fleet heartbeat key missing in OpenBao (run pnpm manar fleet:keygen)',
      );
    const key = createPrivateKey(secret.privateKeyPem);
    if (key.asymmetricKeyType !== 'ed25519')
      throw new Error('Fleet heartbeat key is not Ed25519');
    this.key = key;
    return key;
  }
}

/** The envelope manar-fleet verifies: base64 payload bytes plus their Ed25519 signature. */
export function signPayload(
  payload: HeartbeatPayload,
  key: KeyObject,
): SignedEnvelope {
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8');
  return {
    payload: bytes.toString('base64'),
    signature: sign(null, bytes, key).toString('base64'),
  };
}
