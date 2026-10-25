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
import type { EdgePeer, Prisma } from '../generated/control-client/client';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { gatewayIp, nextFreeAddress, parseCidr } from './edge-net';

/** Postgres channel every replica LISTENs on; the payload is the new version. */
const NOTIFY_CHANNEL = 'manar_edge_peers';
const STATE_ID = 'singleton';
/** Long-poll waiters re-read the version at least this often, so a lost NOTIFY costs seconds, not the whole hold. */
const FALLBACK_POLL_MS = 5_000;
/** How often one replica (whichever holds the lease) recomputes every peer. */
const RECONCILE_MS = 60_000;
/** A tenant whose state cannot be read within this cuts its peers (fail closed) instead of delaying anyone else. */
export const TENANT_READ_TIMEOUT_MS = 2_500;
/** Tenants read in parallel during a refresh. */
const TENANT_CONCURRENCY = 8;
/** Peers per reconcile batch; one short write transaction per batch. */
const BATCH_SIZE = 200;
/** A failed hook is retried after 100 ms and 300 ms, then marks the registry dirty. */
const HOOK_ATTEMPTS = 3;
/** After a failed hook, a full recompute runs this soon. */
const DIRTY_RECONCILE_MS = 5_000;
/** Gateway batch ids are remembered this long. */
const EVENT_BATCH_TTL_MS = 24 * 60 * 60 * 1000;

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
  /** null: not read (cut without a tenant read, or the read failed); keep the row's. */
  allowHosts: string[] | null;
  /** undefined: not read; keep the row's. */
  certNotAfter?: Date | null;
}

type Tx = Prisma.TransactionClient;
type Ticket = {
  id: string;
  tenantId: string;
  agentId: string;
  refreshSeq: number;
};

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

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Rejects after `ms`; the underlying work keeps running but nobody waits for it. */
function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    work,
    new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`timed out after ${ms} ms`)),
        ms,
      );
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * The platform registry of edge (WireGuard) peers, docs/edge.md sections 1 and 2.
 *
 * A refresh takes a ticket per peer (`refreshSeq + 1`), then reads the source of truth outside
 * any lock: control database (platform kill switch, tenant status) and tenant database (agent
 * status, kill switches at every scope, quarantine, AI-system suspension through
 * `KillSwitchService.checkAgent`, certificate revocation and expiry, allow-list). Tenants are read
 * in parallel, each under `TENANT_READ_TIMEOUT_MS`; a tenant that does not answer in time, or a
 * read that fails, cuts its peers (fail closed). Only the write takes the `edge_state` row lock: a
 * peer is written only when no fresher ticket was applied, and the global version is bumped once
 * per transaction when anything visible changed, so versions commit in order.
 *
 * The hooks (`agentChanged`, `tenantChanged`, `allChanged`) are awaited by every code path that
 * changes one of those facts, right after its own commit. They retry, never throw, and on final
 * failure schedule a full recompute; the periodic reconcile (at boot, then every minute, in
 * batches) and an expiry timer (at the earliest certificate expiry) cover the rest.
 */
@Injectable()
export class EdgePeerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EdgePeerService.name);
  /** Long-poll waiters of this instance, woken by NOTIFY or a local commit. */
  private readonly waiters = new Set<() => void>();
  /** In-process queue in front of the row lock: one waiting connection per replica at most. */
  private queue: Promise<unknown> = Promise.resolve();
  private listener?: PgClient;
  private listenerRetry?: NodeJS.Timeout;
  private reconcileTimer?: NodeJS.Timeout;
  private dirtyTimer?: NodeJS.Timeout;
  private expiryTimer?: NodeJS.Timeout;
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
    // Once at boot: a change that landed while no replica ran is not left waiting a minute.
    setImmediate(() => void this.reconcile());
  }

  async onModuleDestroy(): Promise<void> {
    this.stopped = true;
    clearInterval(this.reconcileTimer);
    clearTimeout(this.dirtyTimer);
    clearTimeout(this.expiryTimer);
    clearTimeout(this.listenerRetry);
    this.wake();
    const listener = this.listener;
    this.listener = undefined;
    await listener?.end().catch(() => undefined);
  }

  // ---------------------------------------------------------------------
  // Enrollment
  // ---------------------------------------------------------------------

  /**
   * Read-only check before the enrollment token is spent: the key is not another agent's and,
   * for an agent without a peer, an address is free. `enroll` re-checks under the lock.
   */
  async preflight(input: {
    tenantId: string;
    agentId: string;
    publicKey: string;
  }): Promise<void> {
    const owner = await this.control.edgePeer.findUnique({
      where: { publicKey: input.publicKey },
      select: { tenantId: true, agentId: true },
    });
    if (
      owner &&
      (owner.tenantId !== input.tenantId || owner.agentId !== input.agentId)
    )
      throw new EdgeKeyInUseError();
    const existing = await this.control.edgePeer.findUnique({
      where: {
        tenantId_agentId: { tenantId: input.tenantId, agentId: input.agentId },
      },
      select: { id: true },
    });
    if (existing) return;
    const held = await this.control.edgePeer.findMany({
      select: { address: true },
    });
    if (!nextFreeAddress(this.cidr(), new Set(held.map((r) => r.address))))
      throw new EdgeAddressPoolExhaustedError();
  }

  /**
   * Creates or replaces the agent's one peer (new key, same id and address). A new peer starts
   * cut (`enrolling`) and is then refreshed like any other, so it is never active on a read that
   * predates its row.
   */
  async enroll(input: {
    tenantId: string;
    tenantSlug: string;
    agentId: string;
    agentSlug: string;
    publicKey: string;
  }): Promise<EdgeEnrollment> {
    const cidr = this.cidr();
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
      if (existing) {
        return tx.edgePeer.update({
          where: { id: existing.id },
          data: {
            tenantSlug: input.tenantSlug,
            agentSlug: input.agentSlug,
            publicKey: input.publicKey,
            version: await nextVersion(),
          },
        });
      }
      const held = await tx.edgePeer.findMany({ select: { address: true } });
      const address = nextFreeAddress(
        cidr,
        new Set(held.map((r) => r.address)),
      );
      if (!address) throw new EdgeAddressPoolExhaustedError();
      return tx.edgePeer.create({
        data: {
          tenantId: input.tenantId,
          tenantSlug: input.tenantSlug,
          agentId: input.agentId,
          agentSlug: input.agentSlug,
          publicKey: input.publicKey,
          address,
          state: 'cut',
          cutReason: 'enrolling',
          version: await nextVersion(),
        },
      });
    });
    await this.safely(() => this.refreshIds([peer.id]));
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

  private cidr() {
    return parseCidr(this.config.get('MANAR_EDGE_CIDR', { infer: true }))!;
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

  /**
   * Recomputes every peer, in batches, on the replica holding the reconcile lease (`force`
   * skips the lease: a full recompute after this replica's own hook failed).
   */
  async reconcile(force = false): Promise<void> {
    if (this.stopped) return;
    await this.safely(async () => {
      if (!force) {
        const owned = await this.control.$executeRaw`
          UPDATE "edge_state" SET "reconcileLeaseUntil" = now() + interval '50 seconds'
          WHERE "id" = ${STATE_ID}
            AND ("reconcileLeaseUntil" IS NULL OR "reconcileLeaseUntil" < now())`;
        if (owned === 0) return;
      }
      await this.refresh({});
    }, false);
  }

  private async safely(
    fn: () => Promise<void>,
    markDirtyOnFailure = true,
  ): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      try {
        await fn();
        return;
      } catch (error) {
        if (attempt >= HOOK_ATTEMPTS || this.stopped) {
          this.logger.error(
            `edge peer refresh failed after ${attempt} attempts; full recompute scheduled: ${(error as Error).message}`,
          );
          if (markDirtyOnFailure) this.markDirty();
          return;
        }
        await sleep(100 * 3 ** (attempt - 1));
      }
    }
  }

  private markDirty(): void {
    if (this.dirtyTimer || this.stopped) return;
    this.dirtyTimer = setTimeout(() => {
      this.dirtyTimer = undefined;
      void this.reconcile(true);
    }, DIRTY_RECONCILE_MS);
    this.dirtyTimer.unref();
  }

  /** Every peer matching `where`, `BATCH_SIZE` at a time. */
  private async refresh(where: Prisma.EdgePeerWhereInput): Promise<void> {
    let cursor: string | undefined;
    for (;;) {
      const page = await this.control.edgePeer.findMany({
        where,
        select: { id: true },
        orderBy: { id: 'asc' },
        take: BATCH_SIZE,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      });
      if (page.length > 0) await this.refreshIds(page.map((r) => r.id));
      if (page.length < BATCH_SIZE) break;
      cursor = page[page.length - 1]!.id;
    }
    await this.scheduleExpiry();
  }

  private async refreshIds(ids: string[]): Promise<void> {
    // Tickets first, reads second: a ticket taken later belongs to a read that started later.
    const [, tickets] = await this.control.$transaction([
      this.control.edgePeer.updateMany({
        where: { id: { in: ids } },
        data: { refreshSeq: { increment: 1 } },
      }),
      this.control.edgePeer.findMany({
        where: { id: { in: ids } },
        select: { id: true, tenantId: true, agentId: true, refreshSeq: true },
      }),
    ]);
    const projections = await this.computeAll(tickets);
    await this.locked(async (tx, nextVersion) => {
      const rows = await tx.edgePeer.findMany({ where: { id: { in: ids } } });
      for (const row of rows) {
        const ticket = tickets.find((t) => t.id === row.id);
        const next = projections.get(row.id);
        // A fresher read was already applied: this one may predate a change.
        if (!ticket || !next || row.appliedSeq >= ticket.refreshSeq) continue;
        const allowHosts = next.allowHosts ?? row.allowHosts;
        const visible =
          row.state !== next.state ||
          row.cutReason !== next.cutReason ||
          allowHosts.join('\n') !== row.allowHosts.join('\n');
        await tx.edgePeer.update({
          where: { id: row.id },
          data: {
            appliedSeq: ticket.refreshSeq,
            ...(next.certNotAfter !== undefined
              ? { certNotAfter: next.certNotAfter }
              : {}),
            ...(visible
              ? {
                  state: next.state,
                  cutReason: next.cutReason,
                  allowHosts,
                  version: await nextVersion(),
                }
              : {}),
          },
        });
      }
    });
  }

  /**
   * The peers' state from the source of truth, outside any lock. Cut while any stop condition
   * holds: platform kill switch, tenant not ACTIVE (platform suspension or deletion), then
   * `checkAgent` (agent not ACTIVE; tenant, agent or agent-group kill switch; quarantine; owning
   * AI system suspended or retired), then no unrevoked certificate, or only expired ones.
   */
  private async computeAll(
    tickets: Ticket[],
  ): Promise<Map<string, Projection>> {
    const result = new Map<string, Projection>();
    const platform = await this.control.platformKillSwitch.findUnique({
      where: { id: 'singleton' },
    });
    const byTenant = new Map<string, Ticket[]>();
    for (const t of tickets)
      byTenant.set(t.tenantId, [...(byTenant.get(t.tenantId) ?? []), t]);
    const tenantRows = await this.control.tenant.findMany({
      where: { id: { in: [...byTenant.keys()] } },
      select: { id: true, status: true },
    });
    const status = new Map(tenantRows.map((t) => [t.id, t.status]));

    const groups = [...byTenant];
    const worker = async () => {
      for (let group = groups.shift(); group; group = groups.shift()) {
        const [tenantId, list] = group;
        const cutAll = (cutReason: string) =>
          list.forEach((t) =>
            result.set(t.id, { state: 'cut', cutReason, allowHosts: null }),
          );
        if (platform?.active) cutAll('platform_kill_switch_active');
        else if (status.get(tenantId) !== 'ACTIVE')
          cutAll(`tenant_${(status.get(tenantId) ?? 'missing').toLowerCase()}`);
        else await this.computeTenant(tenantId, list, result);
      }
    };
    await Promise.all(
      Array.from(
        { length: Math.min(TENANT_CONCURRENCY, groups.length) },
        worker,
      ),
    );
    return result;
  }

  /** One tenant: the first read that fails or times out cuts it and every peer not yet read. */
  private async computeTenant(
    tenantId: string,
    list: Ticket[],
    result: Map<string, Projection>,
  ): Promise<void> {
    const killSwitches = this.moduleRef.get(KillSwitchService, {
      strict: false,
    });
    let db: TenantPrismaClient | undefined;
    for (const [i, target] of list.entries()) {
      try {
        db ??= await withTimeout(
          this.tenants.getClient(tenantId),
          TENANT_READ_TIMEOUT_MS,
        );
        const tenantDb = db;
        result.set(
          target.id,
          await withTimeout(
            this.computeAgent(tenantDb, killSwitches, tenantId, target.agentId),
            TENANT_READ_TIMEOUT_MS,
          ),
        );
      } catch (error) {
        this.logger.warn(
          `edge peers of tenant ${tenantId} cut: state lookup failed (${(error as Error).message})`,
        );
        for (const rest of list.slice(i))
          result.set(rest.id, {
            state: 'cut',
            cutReason: 'enforcement_dependency_unavailable',
            allowHosts: null,
          });
        return;
      }
    }
  }

  private async computeAgent(
    db: TenantPrismaClient,
    killSwitches: KillSwitchService,
    tenantId: string,
    agentId: string,
  ): Promise<Projection> {
    const rules = await db.agentEgressRule.findMany({
      where: { agentId },
      select: { host: true },
      orderBy: { host: 'asc' },
    });
    const allowHosts = rules.map((r) => r.host);
    const cut = (cutReason: string, certNotAfter?: Date | null) => ({
      state: 'cut' as const,
      cutReason,
      allowHosts,
      certNotAfter,
    });
    const check = await killSwitches.checkAgent(db, tenantId, agentId);
    if (check.killed) return cut(check.reason ?? 'agent_stopped');
    const certificate = await db.agentCertificate.findFirst({
      where: { agentId, revokedAt: null },
      orderBy: { notAfter: 'desc' },
      select: { notAfter: true },
    });
    if (!certificate) return cut('certificate_revoked', null);
    if (certificate.notAfter.getTime() <= Date.now())
      return cut('certificate_expired', certificate.notAfter);
    return {
      state: 'active',
      cutReason: null,
      allowHosts,
      certNotAfter: certificate.notAfter,
    };
  }

  /** Recomputes active peers when the earliest certificate among them expires. */
  private async scheduleExpiry(): Promise<void> {
    if (!this.enabled || this.stopped) return;
    const next = await this.control.edgePeer.findFirst({
      where: { state: 'active', certNotAfter: { not: null } },
      orderBy: { certNotAfter: 'asc' },
      select: { certNotAfter: true },
    });
    clearTimeout(this.expiryTimer);
    this.expiryTimer = undefined;
    if (!next?.certNotAfter) return;
    // Capped: the timer is re-armed after every refresh anyway.
    const delay = Math.min(
      Math.max(next.certNotAfter.getTime() - Date.now() + 250, 0),
      RECONCILE_MS,
    );
    this.expiryTimer = setTimeout(
      () =>
        void this.safely(() =>
          this.refresh({
            state: 'active',
            certNotAfter: { lte: new Date() },
          }),
        ),
      delay,
    );
    this.expiryTimer.unref();
  }

  /**
   * Runs `fn` holding the `edge_state` row lock (writes only, no tenant reads). `nextVersion()`
   * bumps the global version once per transaction (later calls return the same number) and
   * queues a NOTIFY that Postgres delivers on commit, to every replica's listener.
   */
  private locked<T>(
    fn: (tx: Tx, nextVersion: () => Promise<number>) => Promise<T>,
  ): Promise<T> {
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
        { maxWait: 10_000, timeout: 30_000 },
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

  /** Opened on the first poll; re-opened a second after it drops, without waiting for a poll. */
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
      if (this.stopped) return;
      clearTimeout(this.listenerRetry);
      this.listenerRetry = setTimeout(() => {
        this.ensureListener();
        // Whatever changed while nobody listened reaches waiters now.
        this.wake();
      }, 1_000);
      this.listenerRetry.unref();
    };
    client.on('notification', () => this.wake());
    client.on('error', drop);
    client.on('end', () => drop());
    client
      .connect()
      .then(() => client.query(`LISTEN ${NOTIFY_CHANNEL}`))
      .catch(drop);
  }

  /** For tests: drops the LISTEN connection as a network failure would. */
  dropListenerForTest(): void {
    this.listener?.emit('error', new Error('dropped by test'));
  }

  /** For tests: whether a LISTEN connection is open. */
  get listening(): boolean {
    return this.listener !== undefined;
  }

  /**
   * Gateway egress records as audit events in each peer's tenant, one transaction per tenant.
   * Records for an unknown peer are skipped; a tenant whose write fails (database gone,
   * suspended, unavailable) is skipped and counted, never failing the others. With a `batchId`,
   * each tenant's part is claimed once (`edge_event_batches`, kept a day), so a retried batch
   * writes nothing twice.
   */
  async recordEgress(
    events: EgressEvent[],
    batchId?: string,
  ): Promise<{ accepted: number; skipped: number; duplicates: number }> {
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
    if (batchId)
      await this.control.edgeEventBatch.deleteMany({
        where: { createdAt: { lt: new Date(Date.now() - EVENT_BATCH_TTL_MS) } },
      });
    let accepted = 0;
    let duplicates = 0;
    for (const [tenantId, list] of byTenant) {
      if (batchId) {
        const claimed = await this.control.edgeEventBatch.createMany({
          data: [{ batchId, tenantId }],
          skipDuplicates: true,
        });
        if (claimed.count === 0) {
          duplicates += list.length;
          continue;
        }
      }
      try {
        await this.writeEgress(tenantId, list);
        accepted += list.length;
      } catch (error) {
        this.logger.warn(
          `egress events for tenant ${tenantId} not written (${list.length}): ${(error as Error).message}`,
        );
        skipped += list.length;
        // Unclaim, so the gateway's retry of this batch writes them.
        if (batchId)
          await this.control.edgeEventBatch
            .deleteMany({ where: { batchId, tenantId } })
            .catch(() => undefined);
      }
    }
    return { accepted, skipped, duplicates };
  }

  private async writeEgress(
    tenantId: string,
    list: { event: EgressEvent; agentId: string }[],
  ): Promise<void> {
    const db = await this.tenants.getClient(tenantId);
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
  }
}
