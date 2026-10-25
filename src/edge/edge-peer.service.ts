import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ModuleRef } from '@nestjs/core';
import { Client as PgClient } from 'pg';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TenantNotFoundError } from '../database/tenant-database.errors';
import type { EdgePeer, Prisma } from '../generated/control-client/client';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { gatewayIp, nextFreeAddress, parseCidr } from './edge-net';

/** Postgres channel every replica LISTENs on; the payload is the new version. */
const NOTIFY_CHANNEL = 'manar_edge_peers';
const STATE_ID = 'singleton';
/** Long-poll waiters re-read the version at least this often, so a lost NOTIFY costs seconds, not the whole hold. */
const FALLBACK_POLL_MS = 5_000;
/** How often one replica (whichever holds the advisory lock) recomputes every peer. */
const RECONCILE_MS = 60_000;
const RECONCILE_LOCK_KEY = 'manar-edge-reconcile';

export class EdgeKeyInUseError extends Error {
  constructor() {
    super('This WireGuard public key is already enrolled for another agent');
  }
}

export class EdgeAddressPoolExhaustedError extends Error {
  constructor() {
    super('No free address left in MANAR_EDGE_CIDR');
  }
}

export interface EdgeEnrollment {
  peerId: string;
  address: string;
  gatewayPublicKey: string;
  gatewayEndpoint: string;
  manarAddress: string;
  manarServerName: string;
  proxyAddress: string;
  keepaliveSeconds: number;
}

export interface EdgePeerView {
  id: string;
  publicKey: string;
  address: string;
  state: 'active' | 'cut';
  tenantSlug: string;
  agentSlug: string;
  allowHosts: string[];
}

export interface EdgePeerSnapshot {
  version: number;
  full: boolean;
  peers: EdgePeerView[];
}

export interface EgressEvent {
  peerId: string;
  at: string;
  host: string;
  port: number;
  decision: 'allowed' | 'denied';
  reason: string;
  bytesUp: number;
  bytesDown: number;
  durationMs: number;
  ech?: boolean;
}

interface Projection {
  state: 'active' | 'cut';
  cutReason: string | null;
  /** null: could not be read (cut without a tenant read, or a lookup failed); keep the row's. */
  allowHosts: string[] | null;
}

type Tx = Prisma.TransactionClient;
type Target = { tenantId: string; agentId: string };

const key = (t: Target) => `${t.tenantId}/${t.agentId}`;

function view(row: EdgePeer): EdgePeerView {
  return {
    id: row.id,
    publicKey: row.publicKey,
    address: row.address,
    state: row.state,
    tenantSlug: row.tenantSlug,
    agentSlug: row.agentSlug,
    allowHosts: row.allowHosts,
  };
}

/**
 * The platform registry of edge (WireGuard) peers, docs/edge.md sections 1 and 2.
 *
 * Every write takes the `edge_state` singleton row lock and, when anything changed, bumps the
 * global version in the same transaction, so versions commit in order and a gateway that saw
 * version N has seen every change up to N. State is never written from a caller's claim: every
 * refresh re-reads the tenant database (agent status, kill switches at every scope, quarantine,
 * AI-system suspension through `KillSwitchService.checkAgent`, certificate revocation) and the
 * control database (platform kill switch, tenant status) inside that lock. A lookup failure cuts
 * (fail closed); the periodic reconcile restores the peer once the lookup works again.
 *
 * The hooks (`agentChanged`, `tenantChanged`, `allChanged`) are awaited by every code path that
 * changes one of those facts, right after its own commit, and never throw.
 */
@Injectable()
export class EdgePeerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EdgePeerService.name);
  /** Long-poll waiters of this instance, woken by NOTIFY or a local commit. */
  private readonly waiters = new Set<() => void>();
  /** In-process queue in front of the row lock: one waiting connection per replica at most. */
  private queue: Promise<unknown> = Promise.resolve();
  private listener?: PgClient;
  private reconcileTimer?: NodeJS.Timeout;
  private stopped = false;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly moduleRef: ModuleRef,
    private readonly audit: AuditService,
  ) {}

  get enabled(): boolean {
    return this.config.get('MANAR_EDGE_ENABLED', { infer: true }) === 'true';
  }

  onModuleInit(): void {
    if (!this.enabled) return;
    this.reconcileTimer = setInterval(
      () => void this.reconcile(),
      RECONCILE_MS,
    );
    this.reconcileTimer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    this.stopped = true;
    clearInterval(this.reconcileTimer);
    this.wake();
    const listener = this.listener;
    this.listener = undefined;
    await listener?.end().catch(() => undefined);
  }

  // ---------------------------------------------------------------------
  // Enrollment
  // ---------------------------------------------------------------------

  /** Creates or replaces the agent's one peer (new key, same id and address). */
  async enroll(input: {
    tenantId: string;
    tenantSlug: string;
    agentId: string;
    agentSlug: string;
    publicKey: string;
  }): Promise<EdgeEnrollment> {
    const cidr = parseCidr(
      this.config.get('MANAR_EDGE_CIDR', { infer: true }),
    )!;
    const peer = await this.locked(async (tx, nextVersion) => {
      const owner = await tx.edgePeer.findUnique({
        where: { publicKey: input.publicKey },
      });
      if (
        owner &&
        (owner.tenantId !== input.tenantId || owner.agentId !== input.agentId)
      ) {
        throw new EdgeKeyInUseError();
      }
      const existing = await tx.edgePeer.findUnique({
        where: {
          tenantId_agentId: {
            tenantId: input.tenantId,
            agentId: input.agentId,
          },
        },
      });
      let address = existing?.address ?? null;
      if (!address) {
        const held = await tx.edgePeer.findMany({ select: { address: true } });
        address = nextFreeAddress(cidr, new Set(held.map((r) => r.address)));
        if (!address) throw new EdgeAddressPoolExhaustedError();
      }
      const projection = (await this.compute(tx, [input])).get(key(input))!;
      const version = await nextVersion();
      const data = {
        tenantSlug: input.tenantSlug,
        agentSlug: input.agentSlug,
        publicKey: input.publicKey,
        state: projection.state,
        cutReason: projection.cutReason,
        allowHosts: projection.allowHosts ?? existing?.allowHosts ?? [],
        version,
      };
      return existing
        ? tx.edgePeer.update({ where: { id: existing.id }, data })
        : tx.edgePeer.create({
            data: {
              tenantId: input.tenantId,
              agentId: input.agentId,
              address,
              ...data,
            },
          });
    });
    const gw = gatewayIp(cidr);
    return {
      peerId: peer.id,
      address: peer.address,
      gatewayPublicKey: this.config.get('MANAR_EDGE_GATEWAY_PUBLIC_KEY', {
        infer: true,
      }),
      gatewayEndpoint: this.config.get('MANAR_EDGE_ENDPOINT', { infer: true }),
      manarAddress: `${gw}:443`,
      manarServerName: this.config.get('MANAR_AGENTS_HOST', { infer: true }),
      proxyAddress: `${gw}:3128`,
      keepaliveSeconds: 25,
    };
  }

  // ---------------------------------------------------------------------
  // Refresh hooks (never throw)
  // ---------------------------------------------------------------------

  agentChanged(tenantId: string, agentId: string): Promise<void> {
    return this.safely(() => this.refresh({ tenantId, agentId }));
  }

  agentsChanged(tenantId: string, agentIds: string[]): Promise<void> {
    if (agentIds.length === 0) return Promise.resolve();
    return this.safely(() =>
      this.refresh({ tenantId, agentId: { in: agentIds } }),
    );
  }

  tenantChanged(tenantId: string): Promise<void> {
    return this.safely(() => this.refresh({ tenantId }));
  }

  allChanged(): Promise<void> {
    return this.safely(() => this.refresh({}));
  }

  /** Recomputes every peer on one replica at a time (session advisory lock). */
  async reconcile(): Promise<void> {
    if (this.stopped) return;
    await this.safely(async () => {
      await this.control.$transaction(
        async (tx) => {
          const [row] = await tx.$queryRaw<{ ok: boolean }[]>`
            SELECT pg_try_advisory_xact_lock(hashtext(${RECONCILE_LOCK_KEY})) AS ok`;
          if (!row?.ok) return;
          await this.refresh({});
        },
        { timeout: 300_000 },
      );
    });
  }

  private async safely(fn: () => Promise<void>): Promise<void> {
    try {
      await fn();
    } catch (error) {
      this.logger.error(
        `edge peer refresh failed (the reconcile retries within ${RECONCILE_MS / 1000}s): ${(error as Error).message}`,
      );
    }
  }

  private async refresh(where: Prisma.EdgePeerWhereInput): Promise<void> {
    // Cheap pre-check outside the lock: most changes touch agents with no peer.
    if (
      !(await this.control.edgePeer.findFirst({ where, select: { id: true } }))
    )
      return;
    await this.locked(async (tx, nextVersion) => {
      const rows = await tx.edgePeer.findMany({ where });
      const computed = await this.compute(tx, rows);
      for (const row of rows) {
        const next = computed.get(key(row))!;
        const allowHosts = next.allowHosts ?? row.allowHosts;
        if (
          row.state === next.state &&
          row.cutReason === next.cutReason &&
          allowHosts.join('\n') === row.allowHosts.join('\n')
        )
          continue;
        await tx.edgePeer.update({
          where: { id: row.id },
          data: {
            state: next.state,
            cutReason: next.cutReason,
            allowHosts,
            version: await nextVersion(),
          },
        });
      }
    });
  }

  /**
   * The peer's state from the source of truth. Cut while any stop condition holds: platform kill
   * switch, tenant not ACTIVE (platform suspension or deletion), then `checkAgent` (agent not
   * ACTIVE, i.e. revoked, killed or pending; tenant, agent or agent-group kill switch; quarantine;
   * owning AI system suspended or retired), then no unrevoked certificate.
   */
  private async compute(
    tx: Tx,
    targets: Target[],
  ): Promise<Map<string, Projection>> {
    const result = new Map<string, Projection>();
    const platform = await tx.platformKillSwitch.findUnique({
      where: { id: 'singleton' },
    });
    const tenantRows = await tx.tenant.findMany({
      where: { id: { in: [...new Set(targets.map((t) => t.tenantId))] } },
      select: { id: true, status: true },
    });
    const tenantStatus = new Map(tenantRows.map((t) => [t.id, t.status]));
    const killSwitches = this.moduleRef.get(KillSwitchService, {
      strict: false,
    });

    for (const target of targets) {
      const cut = (cutReason: string, allowHosts: string[] | null = null) =>
        result.set(key(target), { state: 'cut', cutReason, allowHosts });
      if (platform?.active) {
        cut('platform_kill_switch_active');
        continue;
      }
      const status = tenantStatus.get(target.tenantId);
      if (status !== 'ACTIVE') {
        cut(`tenant_${(status ?? 'missing').toLowerCase()}`);
        continue;
      }
      try {
        const db = await this.tenants.getClient(target.tenantId);
        const rules = await db.agentEgressRule.findMany({
          where: { agentId: target.agentId },
          select: { host: true },
          orderBy: { host: 'asc' },
        });
        const allowHosts = rules.map((r) => r.host);
        const check = await killSwitches.checkAgent(
          db,
          target.tenantId,
          target.agentId,
        );
        if (check.killed) {
          cut(check.reason ?? 'agent_stopped', allowHosts);
          continue;
        }
        const certificate = await db.agentCertificate.findFirst({
          where: { agentId: target.agentId, revokedAt: null },
          select: { id: true },
        });
        if (!certificate) {
          cut('certificate_revoked', allowHosts);
          continue;
        }
        result.set(key(target), {
          state: 'active',
          cutReason: null,
          allowHosts,
        });
      } catch (error) {
        this.logger.warn(
          `edge peer of agent ${target.agentId} cut: state lookup failed (${(error as Error).message})`,
        );
        cut('enforcement_dependency_unavailable');
      }
    }
    return result;
  }

  /**
   * Runs `fn` holding the `edge_state` row lock. `nextVersion()` bumps the global version once per
   * transaction (later calls return the same number) and queues a NOTIFY that Postgres delivers on
   * commit, to every replica's listener.
   */
  private locked<T>(
    fn: (tx: Tx, nextVersion: () => Promise<number>) => Promise<T>,
  ): Promise<T> {
    // ponytail: one global lock for every peer write; per-agent locks if refreshes ever queue up.
    const run = this.queue.then(async () => {
      let bumped: number | undefined;
      const result = await this.control.$transaction(
        async (tx) => {
          await tx.$queryRaw`SELECT 1 FROM "edge_state" WHERE "id" = ${STATE_ID} FOR UPDATE`;
          return fn(tx, async () => {
            if (bumped === undefined) {
              const [row] = await tx.$queryRaw<{ version: number }[]>`
                UPDATE "edge_state" SET "version" = "version" + 1
                WHERE "id" = ${STATE_ID} RETURNING "version"`;
              if (!row) throw new Error('edge_state singleton row is missing');
              bumped = row.version;
              await tx.$executeRaw`SELECT pg_notify(${NOTIFY_CHANNEL}, ${String(bumped)})`;
            }
            return bumped;
          });
        },
        { maxWait: 30_000, timeout: 120_000 },
      );
      if (bumped !== undefined) this.wake();
      return result;
    });
    this.queue = run.catch(() => undefined);
    return run;
  }

  // ---------------------------------------------------------------------
  // Gateway sync API
  // ---------------------------------------------------------------------

  async snapshot(after: number): Promise<EdgePeerSnapshot> {
    // Version first, peers second: a change committing in between shows up again on the next
    // poll (an idempotent upsert), never goes missing.
    const state = await this.control.edgeState.findUnique({
      where: { id: STATE_ID },
    });
    const version = state?.version ?? 0;
    if (after <= 0 || after > version) {
      const rows = await this.control.edgePeer.findMany({
        orderBy: { address: 'asc' },
      });
      return { version, full: true, peers: rows.map(view) };
    }
    if (after === version) return { version, full: false, peers: [] };
    const rows = await this.control.edgePeer.findMany({
      where: { version: { gt: after } },
      orderBy: { version: 'asc' },
    });
    return { version, full: false, peers: rows.map(view) };
  }

  /**
   * Long poll: answers at once when anything is newer than `after`, else waits up to `waitMs` for
   * a change. No database connection is held while waiting; the wake comes from this instance's
   * commits, from Postgres NOTIFY (other replicas), or from the fallback re-read.
   */
  async poll(after: number, waitMs: number): Promise<EdgePeerSnapshot> {
    this.ensureListener();
    const deadline = Date.now() + waitMs;
    for (;;) {
      let wake!: () => void;
      const signalled = new Promise<void>((resolve) => {
        wake = resolve;
        this.waiters.add(resolve);
      });
      try {
        const snapshot = await this.snapshot(after);
        const left = deadline - Date.now();
        if (
          snapshot.full ||
          snapshot.peers.length > 0 ||
          left <= 0 ||
          this.stopped
        )
          return snapshot;
        let timer: NodeJS.Timeout | undefined;
        await Promise.race([
          signalled,
          new Promise<void>((resolve) => {
            timer = setTimeout(resolve, Math.min(left, FALLBACK_POLL_MS));
          }),
        ]);
        clearTimeout(timer);
      } finally {
        this.waiters.delete(wake);
      }
    }
  }

  private wake(): void {
    for (const resolve of this.waiters) resolve();
    this.waiters.clear();
  }

  private ensureListener(): void {
    if (this.listener || this.stopped) return;
    const client = new PgClient({
      connectionString: this.config.get('CONTROL_DATABASE_URL', {
        infer: true,
      }),
    });
    this.listener = client;
    const drop = (error?: Error) => {
      if (this.listener !== client) return;
      this.listener = undefined;
      if (error)
        this.logger.warn(`edge LISTEN connection lost: ${error.message}`);
      void client.end().catch(() => undefined);
    };
    client.on('notification', () => this.wake());
    client.on('error', drop);
    client.on('end', () => drop());
    client
      .connect()
      .then(() => client.query(`LISTEN ${NOTIFY_CHANNEL}`))
      .catch(drop);
  }

  /**
   * Gateway egress records as audit events in each peer's tenant. Records for an unknown peer, or
   * a tenant whose database is no longer reachable (suspended or deleted), are skipped and
   * counted. One transaction per tenant.
   */
  async recordEgress(
    events: EgressEvent[],
  ): Promise<{ accepted: number; skipped: number }> {
    const peers = await this.control.edgePeer.findMany({
      where: { id: { in: [...new Set(events.map((e) => e.peerId))] } },
      select: { id: true, tenantId: true, agentId: true },
    });
    const byId = new Map(peers.map((p) => [p.id, p]));
    const byTenant = new Map<
      string,
      { event: EgressEvent; agentId: string }[]
    >();
    let skipped = 0;
    for (const event of events) {
      const peer = byId.get(event.peerId);
      if (!peer) {
        skipped++;
        continue;
      }
      const list = byTenant.get(peer.tenantId) ?? [];
      list.push({ event, agentId: peer.agentId });
      byTenant.set(peer.tenantId, list);
    }
    let accepted = 0;
    for (const [tenantId, list] of byTenant) {
      let db;
      try {
        db = await this.tenants.getClient(tenantId);
      } catch (error) {
        if (!(error instanceof TenantNotFoundError)) throw error;
        skipped += list.length;
        continue;
      }
      const publishers = await db.$transaction(
        async (tx) => {
          const out: (() => void)[] = [];
          for (const { event, agentId } of list) {
            out.push(
              await this.audit.recordInTransaction(tx, tenantId, {
                eventType:
                  event.decision === 'allowed'
                    ? AUDIT_EVENT_TYPES.AGENT_EGRESS_ALLOWED
                    : AUDIT_EVENT_TYPES.AGENT_EGRESS_DENIED,
                actor: { type: 'agent', id: agentId },
                data: {
                  agentId,
                  peerId: event.peerId,
                  at: event.at,
                  host: event.host,
                  port: event.port,
                  reason: event.reason,
                  bytesUp: event.bytesUp,
                  bytesDown: event.bytesDown,
                  durationMs: event.durationMs,
                  ech: event.ech ?? null,
                  source: 'manar-edge-gateway',
                },
              }),
            );
          }
          return out;
        },
        { timeout: 60_000 },
      );
      publishers.forEach((publish) => publish());
      accepted += list.length;
    }
    return { accepted, skipped };
  }
}
