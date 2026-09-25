import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { DEFAULT_PROBE_TIMEOUT_MS, evaluateReadiness } from './readiness';
import type { DependencyProbe, ReadinessReport } from './readiness';
import { checkTcpReachable, parseTcpEndpoint } from './tcp-reachability';

/**
 * Assembles the real dependency probes behind `GET /health/ready` and hands
 * them to the pure engine in `readiness.ts`, which owns the timeout and the
 * ready/not-ready decision.
 *
 * The dependency set is the same nine the deployment's own NetworkPolicy
 * egress list enumerates (deploy/helm/manar-api/values.yaml
 * `networkPolicy.egressTargets`, minus the demo tool server): the control
 * and tenant Postgres databases, OpenFGA, OpenBao, Keycloak, Temporal,
 * Kafka, OpenSearch, Redis, and the manar-ai advisory service. Keeping the
 * two lists aligned is deliberate — a dependency you are allowed to talk to
 * is a dependency worth reporting on, and a diff between the two lists is a
 * real finding either way.
 *
 * ### What "required" means here, and why almost nothing is
 *
 * An unready pod is removed from its Service's endpoints. Every replica of
 * this Deployment shares every dependency below, so marking a dependency
 * required converts *its* outage into a **total** API outage — no replica
 * left to serve the requests that don't touch it. That is the right trade
 * only when the process genuinely cannot serve: when the alternative is
 * 500ing every request anyway.
 *
 * By that bar exactly two dependencies qualify, and both of them sit on
 * every authenticated request path:
 *
 * - **The control database.** Every request resolves its tenant through it
 *   before anything else can happen.
 * - **OpenFGA.** Every authorization decision goes through
 *   `OpenFgaClientService.check`, which deliberately *throws* on any
 *   transport failure rather than swallowing it (see its own doc comment —
 *   an authorization store that is unreachable must never be read as
 *   "allowed"). With OpenFGA gone, every authorized route 500s.
 *
 * Everything else is optional **by the codebase's own explicit design**,
 * not by convenience: Kafka, OpenSearch, and all three Redis clients boot
 * best-effort and swallow their own failures; `KeycloakAdminClient` does no
 * eager I/O and is only touched by role-management routes; Temporal's loss
 * stops approval workflows from progressing but not the API from answering;
 * and the AI advisory service is advisory by mandate (Section 80 — an AI
 * outage must never change a deterministic authorization outcome, and every
 * `AiAdvisoryClient` method returns `null` rather than throwing). Losing
 * any of them shows up as `status: 'degraded'` with the failure spelled out
 * per-dependency, while `ready` stays `true` and the replica keeps serving.
 *
 * That last one is a hard requirement of this release, not a preference: an
 * optional-AI outage must **not** become a perpetual readiness failure for
 * an otherwise perfectly valid deterministic profile.
 */
@Injectable()
export class ReadinessService {
  /**
   * Hard per-probe budget. Comfortably under the kubelet's own
   * `readinessProbe.timeoutSeconds: 3` (deploy/helm/manar-api/values.yaml)
   * so a slow dependency is reported as `stale` in a real response body,
   * rather than showing up as an opaque kubelet-side probe timeout with
   * nothing to read.
   */
  private static readonly PROBE_TIMEOUT_MS = DEFAULT_PROBE_TIMEOUT_MS;

  /**
   * How many tenant databases the tenant-Postgres probe samples per check.
   *
   * One. This probe exists to smoke-test the *whole* tenant path end to end
   * (control DB lookup -> secret resolution -> tenant connection), not to
   * inventory every tenant: a per-tenant fan-out would make the cost of a
   * health check grow with the customer base and would thrash
   * `TenantDatabaseManager`'s bounded client cache (`TENANT_DB_CLIENT_CACHE_MAX`)
   * on every kubelet cycle.
   */
  private static readonly TENANT_DB_SAMPLE_SIZE = 1;

  readonly probes: readonly DependencyProbe[];

  constructor(
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly controlPrisma: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {
    this.probes = this.buildProbes();
  }

  async check(): Promise<ReadinessReport> {
    return evaluateReadiness(this.probes, ReadinessService.PROBE_TIMEOUT_MS);
  }

  private buildProbes(): DependencyProbe[] {
    return [
      {
        name: 'postgres-control',
        required: true,
        impact:
          'Tenant resolution and every control-plane read; the process can serve nothing without it.',
        run: async () => {
          // A real query, not a connection-pool inspection: Prisma's pool
          // happily reports a live connection to a server that has since
          // stopped answering (failover, connection limit exhausted,
          // recovery mode). `SELECT 1` is the same idiom
          // `TenantDatabaseManager.checkHealth` already uses.
          await this.controlPrisma.$queryRaw`SELECT 1`;
        },
      },
      {
        name: 'postgres-tenant',
        required: false,
        impact:
          'Per-tenant reads/writes for the sampled tenant; other tenants are unaffected, so this never gates traffic.',
        run: async () => this.probeSampledTenantDatabases(),
      },
      {
        name: 'openfga',
        required: true,
        impact:
          'Every authorization decision; OpenFgaClientService.check throws on transport failure rather than failing open, so an unreachable store means every authorized route 500s.',
        run: this.tcpProbe('OPENFGA_API_URL'),
      },
      {
        name: 'openbao',
        required: false,
        impact:
          'Tenant database credential resolution and agent PKI issuance. Already-cached tenant clients keep working, so this degrades rather than gates.',
        // Not a TCP probe (Gate 0 finding F1): a dev-mode OpenBao restarted
        // with an empty PKI still accepts connections while every enrollment
        // 500s. The intermediate's public CA chain is unauthenticated and
        // exists only once the agent PKI is mounted.
        run: async () => {
          const response = await fetch(
            `${this.configService.get('OPENBAO_ADDR', { infer: true })}/v1/${this.configService.get('OPENBAO_PKI_INTERMEDIATE_PATH', { infer: true })}/ca_chain`,
          );
          if (!response.ok) {
            throw new Error(
              `agent PKI not mounted (ca_chain HTTP ${response.status})`,
            );
          }
        },
      },
      {
        name: 'keycloak',
        required: false,
        impact:
          'Role grant/revoke and tenant realm provisioning only — JWT verification uses cached JWKS, so ordinary authenticated traffic is unaffected.',
        run: this.tcpProbe('KEYCLOAK_BASE_URL'),
      },
      {
        name: 'temporal',
        required: false,
        impact:
          'Approval and retention workflows stop progressing; already-issued grants and every synchronous route keep working.',
        run: this.tcpProbe('TEMPORAL_ADDRESS'),
      },
      {
        name: 'kafka',
        required: false,
        impact:
          'Downstream audit-event fan-out. The authoritative audit row is the Postgres write, which is unaffected — KafkaPublisherService never throws to its caller.',
        run: this.tcpProbe('KAFKA_BROKERS'),
      },
      {
        name: 'opensearch',
        required: false,
        impact:
          'Audit search/browse. Indexing catches up automatically once reachable again; the tamper-evident chain in Postgres is unaffected.',
        run: this.tcpProbe('OPENSEARCH_NODE'),
      },
      {
        name: 'redis',
        required: false,
        impact:
          'Rate-limit counters, idempotency replay cache, and live-event SSE fan-out. Rate limiting fails open by design (see TenantThrottlerGuard).',
        run: this.tcpProbe('REDIS_URL'),
      },
      {
        name: 'ai-advisory',
        required: false,
        impact:
          'Optional AI advice only (Section 80). The deterministic policy/risk pipeline runs standalone and is never allowed to change outcome on an AI outage — this must never gate readiness.',
        run: this.tcpProbe('AI_ADVISORY_GRPC_TARGET'),
      },
    ];
  }

  /**
   * A reachability probe against whatever address `configKey` holds.
   *
   * An address the parser can't read resolves as `'degraded'` rather than
   * rejecting: a malformed or unset dependency address is a configuration
   * problem to surface in the body, never grounds for this endpoint to
   * claim the dependency is down (and, for a required dependency, to empty
   * the Service's endpoint list over a typo).
   *
   * See `tcp-reachability.ts` for why these are connect-only checks rather
   * than real client calls.
   */
  private tcpProbe(
    configKey:
      | 'OPENFGA_API_URL'
      | 'OPENBAO_ADDR'
      | 'KEYCLOAK_BASE_URL'
      | 'TEMPORAL_ADDRESS'
      | 'KAFKA_BROKERS'
      | 'OPENSEARCH_NODE'
      | 'REDIS_URL'
      | 'AI_ADVISORY_GRPC_TARGET',
  ): () => Promise<void | 'degraded'> {
    return async () => {
      const raw = this.configService.get(configKey, { infer: true });
      const endpoint = typeof raw === 'string' ? parseTcpEndpoint(raw) : null;
      if (!endpoint) return 'degraded';
      await checkTcpReachable(endpoint);
    };
  }

  /**
   * `SELECT 1` against a bounded sample of ACTIVE tenants' own databases,
   * via `TenantDatabaseManager.checkHealth` — the method that has carried a
   * "exposed for a future /health/ready aggregation" comment since Phase 2,
   * finally wired in.
   *
   * Reports `'degraded'` (not a failure) when there is nothing to sample: a
   * freshly installed control plane legitimately has no ACTIVE tenants, and
   * a probe that has nothing to check has observed nothing — reporting that
   * honestly beats reporting a green it did not earn.
   */
  private async probeSampledTenantDatabases(): Promise<void | 'degraded'> {
    const tenants = await this.controlPrisma.tenant.findMany({
      where: { status: 'ACTIVE' },
      // Deterministic ordering so consecutive probes hit the same tenant
      // and reuse its cached client, instead of walking the tenant list and
      // evicting the cache a replica's real traffic depends on.
      orderBy: { id: 'asc' },
      take: ReadinessService.TENANT_DB_SAMPLE_SIZE,
      select: { id: true },
    });

    if (tenants.length === 0) return 'degraded';

    for (const tenant of tenants) {
      await this.tenantDatabaseManager.checkHealth(tenant.id);
    }
  }
}
