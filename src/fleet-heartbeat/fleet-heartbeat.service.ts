import {
  randomBytes,
  sign,
  createPrivateKey,
  type KeyObject,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
  Inject,
  Injectable,
  Optional,
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
import { PlatformOpsService } from '../platform/platform-ops.service';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const VERSION = (require('../../package.json') as { version: string }).version;

const ts = z.iso.datetime({ offset: true });

const BackupFileSchema = z.object({
  status: z.enum(['ok', 'failed', 'running', 'unknown']),
  lastBackupAt: ts.nullable().default(null),
  lastRestoreTestAt: ts.nullable().default(null),
  /** Result of the last restore drill, written by the backup job when it runs one. */
  lastRestoreTestStatus: z.enum(['ok', 'failed']).nullable().default(null),
  /** How long the last restore drill took, in seconds (a timed drill each time). */
  lastRestoreTestSeconds: z
    .number()
    .int()
    .min(0)
    .max(604_800)
    .nullable()
    .default(null),
});

/**
 * Where the per-tenant catalog section comes from: the catalog workstream's `CatalogService.view`
 * (bound to this token once it is on main). Unbound, the section is left out.
 */
export const HEARTBEAT_TENANT_CATALOG = Symbol('HEARTBEAT_TENANT_CATALOG');
export interface TenantCatalogSource {
  view(tenantId: string): Promise<{
    features: Record<'assistant' | 'watcher' | 'packs' | 'llm_proxy', boolean>;
    packs: { id: string; version: number; enabled: boolean }[];
    model: {
      provider: string;
      model: string;
      uaeResidency: boolean;
      monthlyTokenQuota: number | null;
    } | null;
    usage: { month: string; tokens: number | null };
    connectors:
      | {
          name: string;
          type: string;
          protocol: string;
          enabled: boolean;
          credentialExpiresAt: Date | string | null;
        }[]
      | null;
  }>;
}

const TenantSectionSchema = z
  .object({
    tenantId: z.uuid(),
    catalog: z
      .object({
        features: z
          .object({
            assistant: z.boolean(),
            watcher: z.boolean(),
            packs: z.boolean(),
            llm_proxy: z.boolean(),
          })
          .strict(),
        packs: z
          .array(
            z
              .object({
                id: z.string().regex(/^[a-z][a-z0-9-]{1,62}$/),
                version: z.number().int().min(1).max(100_000),
                enabled: z.boolean(),
              })
              .strict(),
          )
          .max(100),
        model: z
          .object({
            provider: z.enum(['ollama', 'azure_openai', 'core42_compass']),
            model: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/),
            uaeResidency: z.boolean(),
            monthlyTokenQuota: z
              .number()
              .int()
              .min(1)
              .max(1_000_000_000_000)
              .nullable(),
          })
          .strict()
          .nullable(),
      })
      .strict(),
    llmTokensMonth: z
      .object({
        month: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/),
        tokens: z.number().int().min(0).nullable(),
      })
      .strict(),
    connectors: z
      .array(
        z
          .object({
            name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/),
            type: z.string().min(1).max(50),
            protocol: z.string().regex(/^[A-Z][A-Z0-9_]{0,31}$/),
            enabled: z.boolean(),
            credentialExpiresAt: ts.nullable(),
          })
          .strict(),
      )
      .max(100),
  })
  .strict();

const name = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);

/**
 * The payload, validated before it is signed: the same strict schema manar-fleet applies on
 * receipt (`HeartbeatPayloadSchema` there). Anything outside it, a tenant id or a name, fails
 * here and nothing is sent. Change both together, and deploy manar-fleet first.
 */
export const HeartbeatPayloadSchema = z
  .object({
    v: z.literal(1),
    deploymentId: z.uuid(),
    timestamp: ts,
    nonce: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/),
    version: z.string().regex(/^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/),
    gitSha: z.string().regex(/^[0-9A-Za-z._-]{0,64}$/),
    health: z
      .object({
        status: z.enum(['ok', 'degraded', 'down']),
        checks: z.record(name, z.enum(['up', 'down'])),
        openbaoSealed: z.boolean().nullable().optional(),
      })
      .strict(),
    backup: z
      .object({
        status: z.enum(['ok', 'failed', 'running', 'unknown']),
        lastBackupAt: ts.nullable(),
        lastRestoreTestAt: ts.nullable(),
        lastRestoreTestStatus: z.enum(['ok', 'failed']).nullable().optional(),
        lastRestoreTestSeconds: z
          .number()
          .int()
          .min(0)
          .max(604_800)
          .nullable()
          .optional(),
      })
      .strict(),
    counts: z.record(name, z.number().int().min(0)),
    expiries: z
      .array(
        z
          .object({
            kind: z.enum(['agent_ca', 'tls_server', 'tool_credential']),
            notAfter: ts,
          })
          .strict(),
      )
      .max(64)
      .optional(),
    auditChain: z
      .object({
        status: z.enum(['ok', 'broken', 'unknown']),
        tenantsChecked: z.number().int().min(0),
        tenantsBroken: z.number().int().min(0),
        verifiedAt: ts.nullable(),
      })
      .strict()
      .optional(),
    usage: z
      .object({
        months: z
          .array(
            z
              .object({
                month: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/),
                decisions: z.number().int().min(0),
              })
              .strict(),
          )
          .max(12),
      })
      .strict()
      .optional(),
    killSwitch: z
      .object({ active: z.boolean(), activatedAt: ts.nullable() })
      .strict()
      .optional(),
    tenants: z.array(TenantSectionSchema).max(200).optional(),
  })
  .strict()
  .refine(
    (p) =>
      Object.keys(p.health.checks).length <= 32 &&
      Object.keys(p.counts).length <= 32,
  );

export type HeartbeatPayload = z.infer<typeof HeartbeatPayloadSchema>;

/** manar-fleet's EnvelopeSchema bound on the base64 payload; change both together. */
export const HEARTBEAT_MAX_PAYLOAD_CHARS = 262_144;

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
    private readonly ops: PlatformOpsService,
    @Optional()
    @Inject(HEARTBEAT_TENANT_CATALOG)
    private readonly catalog?: TenantCatalogSource,
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
    const key = await this.signingKey();
    const payload = await this.payload();
    let env = signPayload(payload, key);
    // manar-fleet refuses a larger payload, which would silence the whole heartbeat: the
    // per-tenant section goes first, then nothing is sent.
    if (env.payload.length > HEARTBEAT_MAX_PAYLOAD_CHARS && payload.tenants) {
      this.logger.warn(
        `Fleet heartbeat: per-tenant section left out (${payload.tenants.length} tenants, payload over ${HEARTBEAT_MAX_PAYLOAD_CHARS} characters)`,
      );
      env = signPayload({ ...payload, tenants: undefined }, key);
    }
    if (env.payload.length > HEARTBEAT_MAX_PAYLOAD_CHARS)
      throw new Error(
        'Fleet heartbeat payload over the size manar-fleet accepts',
      );
    return env;
  }

  /** Builds the payload and validates it against the strict schema; throws if it does not fit. */
  async payload(): Promise<HeartbeatPayload> {
    const report = await this.readiness.check();
    const checks: Record<string, 'up' | 'down'> = {};
    for (const [name, dep] of Object.entries(report.dependencies))
      checks[name] = dep.status === 'ok' ? 'up' : 'down';
    // Each ops section is best effort: one that cannot be read is left out, never guessed.
    const optional = async <T>(f: () => Promise<T>) => {
      try {
        return await f();
      } catch {
        return undefined;
      }
    };
    const [openbaoSealed, expiries, auditChain, months, killSwitch] =
      await Promise.all([
        this.ops.openbaoSealed(),
        optional(() => this.ops.expiries()),
        optional(() => this.ops.auditChain()),
        optional(() => this.ops.usageMonths()),
        optional(() => this.ops.killSwitchState()),
      ]);
    const tenants = await optional(() => this.tenantSections());
    return HeartbeatPayloadSchema.parse({
      v: 1,
      deploymentId: this.config.get('FLEET_DEPLOYMENT_ID', { infer: true }),
      timestamp: new Date().toISOString(),
      nonce: randomBytes(16).toString('hex'),
      version: VERSION,
      gitSha: this.config.get('MANAR_GIT_SHA', { infer: true }) ?? 'unknown',
      health: {
        status: report.status === 'unhealthy' ? 'down' : report.status,
        checks,
        openbaoSealed,
      },
      backup: await this.backup(),
      counts: await this.counts(),
      expiries,
      auditChain,
      usage: months ? { months } : undefined,
      killSwitch,
      tenants,
    });
  }

  /**
   * One catalog section per ACTIVE tenant. A tenant whose section cannot be read or does not fit
   * the schema is left out (and logged by id), so one bad row never stops the heartbeat.
   */
  private async tenantSections() {
    if (!this.catalog) return undefined;
    const rows = await this.control.tenant.findMany({
      where: { status: 'ACTIVE' },
      select: { id: true },
      orderBy: { id: 'asc' },
      take: 200,
    });
    const out: z.infer<typeof TenantSectionSchema>[] = [];
    for (const { id } of rows) {
      try {
        const v = await this.catalog.view(id);
        out.push(
          TenantSectionSchema.parse({
            tenantId: id,
            catalog: { features: v.features, packs: v.packs, model: v.model },
            llmTokensMonth: v.usage,
            connectors: (v.connectors ?? []).map((c) => ({
              name: c.name,
              type: c.type,
              protocol: c.protocol,
              enabled: c.enabled,
              credentialExpiresAt:
                c.credentialExpiresAt instanceof Date
                  ? c.credentialExpiresAt.toISOString()
                  : c.credentialExpiresAt,
            })),
          }),
        );
      } catch {
        this.logger.warn(
          `Fleet heartbeat: catalog section of tenant ${id} left out`,
        );
      }
    }
    return out;
  }

  private async backup(): Promise<HeartbeatPayload['backup']> {
    const file = this.config.get('FLEET_BACKUP_STATUS_FILE', { infer: true });
    const unknown = {
      status: 'unknown' as const,
      lastBackupAt: null,
      lastRestoreTestAt: null,
      lastRestoreTestStatus: null,
      lastRestoreTestSeconds: null,
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
