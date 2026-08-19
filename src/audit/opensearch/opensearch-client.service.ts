import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Client } from '@opensearch-project/opensearch';
import type { AppConfig } from '../../config/env.validation';

const RETRY_ATTEMPTS = 3;
const RETRY_DELAY_MS = 300;

/** The document shape upserted into OpenSearch for one `AuditEvent` (Section 45/29). */
export interface AuditEventDocument {
  eventId: string;
  tenantId: string;
  sequence: number;
  eventType: string;
  correlationId: string;
  actor: unknown;
  timestamp: string;
  data: unknown;
  previousHash: string | null;
  eventHash: string;
  /**
   * Phase 11b Part 1 (`GET /audit`, Section 66's filter set) — real,
   * indexed (`keyword`/`long`) top-level fields derived from `actor`/`data`
   * by `extractAuditSearchFields` (`audit-search-fields.ts`), added
   * *alongside* the unindexed `actor`/`data` blobs above (never replacing
   * them — those two remain the verbatim, tamper-evident-chain-hashed
   * record). Optional: not every `eventType`'s `data` carries every
   * dimension — see that module's own doc comment.
   */
  agentId?: string;
  taskId?: string;
  toolId?: string;
  actionId?: string;
  decision?: string;
  riskScore?: number;
}

/**
 * The Phase 11b Part 1 search-field mapping — split out from the base
 * mapping in `ensureIndexExists` so it can also be `putMapping`'d onto an
 * index that already existed before this phase (OpenSearch's PUT mapping
 * API only ever *adds* new fields to an existing mapping, never redefines
 * one already present — safe to call unconditionally, every time, whether
 * the index was just created or already existed with the pre-Phase-11b
 * mapping).
 */
const SEARCH_FIELD_PROPERTIES = {
  agentId: { type: 'keyword' },
  taskId: { type: 'keyword' },
  toolId: { type: 'keyword' },
  actionId: { type: 'keyword' },
  decision: { type: 'keyword' },
  riskScore: { type: 'long' },
} as const;

/**
 * Phase 9b (OpenSearch Indexing, Section 45). Thin wrapper around a single
 * `@opensearch-project/opensearch` client connection — the one place this
 * codebase talks to OpenSearch. Through Phase 11b Part 1, deliberately
 * minimal: no query/search surface was exposed (nothing in the design
 * spec asked for a `GET /audit` endpoint yet) — this service existed
 * purely to make `AuditEvent` rows *indexed and idempotently upsertable*,
 * the disaster-recovery/reindex story, and the redelivery-doesn't-double-
 * index invariant, all real and testable. Phase 11b Part 1 adds exactly
 * one query method (`search`, below) for `GET /audit` — still the one
 * place this codebase talks to OpenSearch; `AuditSearchService`
 * (`src/audit/audit-search.service.ts`) builds the query DSL and owns the
 * HTTP-facing filter/pagination contract, but never holds its own client.
 *
 * A single, tenant-tagged index (every document carries `tenantId`, see
 * `AuditEventDocument`) rather than one index per tenant — simpler to
 * create/reindex/query for this phase's MVP scope, consistent with "no
 * OpenSearch sharding/lifecycle policies beyond a sane default" being
 * explicitly out of scope.
 *
 * `data`/`actor` are mapped as `enabled: false` — stored verbatim (so the
 * full document round-trips byte-for-byte through `_source`) but never
 * parsed into the index's field mapping. `AuditEvent.data` is a
 * deliberately heterogeneous JSON blob across ~15 different `eventType`s
 * (Section 46) — e.g. one event's `data.riskScore` is a number while
 * another `eventType`'s `data` has no such field at all, and a future
 * event type could reuse a key name for an incompatible type. Letting
 * OpenSearch's dynamic mapping infer types from the first document it
 * sees for each key would risk a *mapping conflict* rejecting a later,
 * differently-shaped document outright — silently breaking indexing for
 * an entire `eventType` the first time two of its documents disagree on a
 * nested field's type. `enabled: false` sidesteps that class of failure
 * entirely: correctness (every event is indexed, retrievable by
 * `eventId`, and unindexed fields still returned in `_source`) over
 * queryability-inside-`data`, which nothing in this phase's scope needs.
 */
@Injectable()
export class OpenSearchIndexService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OpenSearchIndexService.name);
  readonly indexName: string;
  private readonly client: Client;
  /** Set once `ensureIndexExists` has actually confirmed/created the index and merged in `SEARCH_FIELD_PROPERTIES` — skips the repeat `exists`+`putMapping` round trip on every subsequent call within this process's lifetime (still re-checked from scratch after any failure, and always on a fresh process). */
  private indexEnsured = false;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {
    this.indexName = this.configService.get('OPENSEARCH_AUDIT_INDEX', {
      infer: true,
    });
    this.client = new Client({
      node: this.configService.get('OPENSEARCH_NODE', { infer: true }),
    });
  }

  /**
   * Best-effort index creation at boot — deliberately never lets an
   * OpenSearch outage fail the whole Nest application's startup, the same
   * posture `KafkaPublisherService.onModuleInit` already establishes for
   * Kafka (`docs/audit-chain.md`). If this fails, every subsequent
   * `upsertAuditEvent` call still calls `ensureIndexExists` first (see
   * that method), so indexing catches up automatically once OpenSearch
   * becomes reachable.
   */
  async onModuleInit(): Promise<void> {
    try {
      await this.ensureIndexExists();
    } catch (error) {
      this.logger.warn(
        `Could not confirm OpenSearch index "${this.indexName}" exists at startup (will retry lazily on first upsert): ${errorMessage(error)}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.client.close();
    } catch (error) {
      this.logger.warn(
        `Error closing OpenSearch client during shutdown: ${errorMessage(error)}`,
      );
    }
  }

  /**
   * Idempotent — `indices.create` on an already-existing index is a
   * documented 400 (`resource_already_exists_exception`), swallowed here,
   * the same "resolve-or-create, no separate init job" posture
   * `KafkaPublisherService.ensureTopicExists`/`OpenFgaClientService.onModuleInit`
   * already establish elsewhere in this codebase.
   *
   * Phase 11b Part 1: after confirming the index exists (freshly created
   * here, or already present from before this phase), also `putMapping`s
   * `SEARCH_FIELD_PROPERTIES` — an additive-only operation (OpenSearch's
   * PUT mapping API can only add fields, never redefine an existing one),
   * so this is safe to run on every call, and is what makes the new
   * `GET /audit` filters work against an index that already existed
   * before this phase without requiring a manual reindex.
   */
  async ensureIndexExists(): Promise<void> {
    if (this.indexEnsured) return;
    await this.withRetry('ensureIndexExists', async () => {
      const exists = await this.client.indices.exists({
        index: this.indexName,
      });
      if (!exists.body) {
        try {
          await this.client.indices.create({
            index: this.indexName,
            body: {
              mappings: {
                properties: {
                  eventId: { type: 'keyword' },
                  tenantId: { type: 'keyword' },
                  sequence: { type: 'long' },
                  eventType: { type: 'keyword' },
                  correlationId: { type: 'keyword' },
                  timestamp: { type: 'date' },
                  previousHash: { type: 'keyword' },
                  eventHash: { type: 'keyword' },
                  // See class doc comment for why these two are unindexed.
                  actor: { type: 'object', enabled: false },
                  data: { type: 'object', enabled: false },
                  ...SEARCH_FIELD_PROPERTIES,
                },
              },
            },
          });
          return;
        } catch (error) {
          if (!isResourceAlreadyExists(error)) throw error;
        }
      }

      await this.client.indices.putMapping({
        index: this.indexName,
        body: { properties: SEARCH_FIELD_PROPERTIES },
      });
    });
    this.indexEnsured = true;
  }

  /**
   * Upserts one `AuditEvent` by `eventId` (Section 29/45's mandatory
   * idempotency contract) — OpenSearch's Index API with an explicit `id`
   * always *replaces* any existing document at that id rather than
   * appending, so redelivering the same Kafka message (at-least-once
   * delivery, never exactly-once) or re-running `audit:reindex` over
   * already-indexed events never produces a duplicate.
   */
  async upsertAuditEvent(document: AuditEventDocument): Promise<void> {
    await this.ensureIndexExists();
    await this.withRetry('upsertAuditEvent', () =>
      this.client.index({
        index: this.indexName,
        id: document.eventId,
        body: document,
        // Tests assert on read-after-write within the same process — a
        // near-real-time-only refresh policy would make those flaky for no
        // production benefit at this event volume.
        refresh: true,
      }),
    );
  }

  /** Fetches one document by `eventId` — used by tests and `audit:reindex`'s own verification. */
  async getById(eventId: string): Promise<AuditEventDocument | null> {
    try {
      const response = await this.withRetry('getById', () =>
        this.client.get({ index: this.indexName, id: eventId }),
      );
      const body = response.body as { _source?: AuditEventDocument };
      return body._source ?? null;
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  }

  /**
   * Phase 11b Part 1 — the one query method this service exposes (see
   * class doc comment). A thin, typed pass-through to OpenSearch's Query
   * DSL: `AuditSearchService` builds `query`/`sort`/`searchAfter`, this
   * method just runs it and returns the raw hits (`_source` documents plus
   * each hit's own `sort` values, needed to compute the next
   * `search_after` cursor) — no filter/pagination-shape knowledge lives
   * here, matching this class's existing "index plumbing only" scope.
   */
  async search(params: {
    query: Record<string, unknown>;
    sort: Record<string, 'asc' | 'desc'>[];
    size: number;
    searchAfter?: (string | number)[];
  }): Promise<{ hits: AuditEventDocument[]; sortValues: unknown[][] }> {
    await this.ensureIndexExists();
    const response = await this.withRetry('search', () =>
      this.client.search({
        index: this.indexName,
        body: {
          query: params.query,
          sort: params.sort,
          size: params.size,
          ...(params.searchAfter ? { search_after: params.searchAfter } : {}),
        },
      }),
    );
    const hits = (
      response.body as unknown as {
        hits: { hits: { _source: AuditEventDocument; sort?: unknown[] }[] };
      }
    ).hits.hits;
    return {
      hits: hits.map((hit) => hit._source),
      sortValues: hits.map((hit) => hit.sort ?? []),
    };
  }

  /** Total indexed document count — used by tests (the reindex-reconstructs-everything assertion). */
  async count(tenantId?: string): Promise<number> {
    await this.ensureIndexExists();
    const response = await this.withRetry('count', () =>
      this.client.count({
        index: this.indexName,
        body: tenantId
          ? { query: { term: { tenantId } } }
          : { query: { match_all: {} } },
      }),
    );
    return response.body.count;
  }

  /**
   * DESTRUCTIVE — deletes every indexed document for one tenant (never the
   * whole shared index, which other concurrently-running test files' own
   * tenants also index into). Only ever called by tests proving the
   * reindex disaster-recovery path (Section 45: "drop/empty the OpenSearch
   * index, run reindex, confirm it's fully reconstructable from Postgres
   * alone") — no application code path calls this.
   */
  async dangerouslyDeleteAllForTenantForTests(tenantId: string): Promise<void> {
    await this.ensureIndexExists();
    await this.withRetry('dangerouslyDeleteAllForTenantForTests', () =>
      this.client.deleteByQuery({
        index: this.indexName,
        refresh: true,
        body: { query: { term: { tenantId } } },
      }),
    );
  }

  /**
   * A small bounded retry (short fixed delay) for transient failures — the
   * same "keep it simple" retry shape `KafkaPublisherService.publish`
   * already uses (`docs/audit-chain.md`). Real-world local/CI runs share
   * one OpenSearch instance across many concurrently-running e2e test
   * files, each hammering the same shared index (Section 45's own "single,
   * tenant-tagged index" choice) — a transient connection reset or a
   * momentary bulk/search thread-pool rejection under that concurrent load
   * is expected, not a bug in this service, and shouldn't fail an entire
   * test (or a real indexing/reindex run) outright.
   */
  private async withRetry<T>(
    operation: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= RETRY_ATTEMPTS; attempt += 1) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        if (isNotFound(error) || isResourceAlreadyExists(error)) throw error;
        if (attempt === RETRY_ATTEMPTS) break;
        this.logger.warn(
          `OpenSearch "${operation}" failed (attempt ${attempt}/${RETRY_ATTEMPTS}), retrying: ${errorMessage(error)}`,
        );
        await delay(RETRY_DELAY_MS * attempt);
      }
    }
    throw lastError;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    const body = (error as { meta?: { body?: unknown } }).meta?.body;
    return body ? `${error.message} ${JSON.stringify(body)}` : error.message;
  }
  return String(error);
}

function isResourceAlreadyExists(error: unknown): boolean {
  const status = (error as { statusCode?: number } | undefined)?.statusCode;
  return status === 400;
}

function isNotFound(error: unknown): boolean {
  const status = (error as { statusCode?: number } | undefined)?.statusCode;
  return status === 404;
}
