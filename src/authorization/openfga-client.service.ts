import { Agent as HttpAgent } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';
import axios from 'axios';
import { readFileSync } from 'node:fs';
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ClientWriteRequestOnDuplicateWrites,
  ClientWriteRequestOnMissingDeletes,
  OpenFgaClient,
  type Condition,
  type TypeDefinition,
} from '@openfga/sdk';
import { transformer } from '@openfga/syntax-transformer';
import { AppConfig } from '../config/env.validation';

export interface TupleKey {
  user: string;
  relation: string;
  object: string;
  /** A conditional tuple (staff elevations and timed grants: `within_window`). Writes only. */
  condition?: { name: string; context?: Record<string, unknown> };
}

/**
 * Owns the single `OpenFgaClient` instance for this process and resolves
 * (or creates) the store + authorization model it talks to at boot —
 * see openfga.config.ts's doc comment for why this is an automatic,
 * every-boot resolution rather than a separate manually-invoked init
 * script the way OpenBao's CA bootstrap is.
 *
 * A thin, honest wrapper: `write`/`check` below do not catch or interpret
 * errors — a network failure, a malformed store, or OpenFGA being
 * completely down all surface as a rejected promise, exactly as the SDK
 * throws it (or, if OpenFGA was already unreachable at boot — see
 * `onModuleInit` — a clear "not initialized" error). `AuthorizationService`
 * is where the fail-closed *policy* decision belongs (Section 22: if any
 * check can't be evaluated trustworthily, DENY) — this service's job is
 * only to make the call honestly, never to silently swallow a failure into
 * an ambiguous result.
 *
 * `onModuleInit` itself deliberately does NOT let a store/model resolution
 * failure crash the whole application's bootstrap: if OpenFGA happens to
 * be unreachable at boot (a transient outage, a slow-starting sidecar,
 * ...), this service logs the failure and stays in a "not ready" state
 * rather than taking the entire app down with it — every subsequent
 * `check()`/`write()` call then fails fast with a clear error (which
 * `AuthorizationService` converts to DENY, same as a mid-flight outage
 * would), and the app keeps serving every *other* endpoint normally. This
 * is also what makes the OpenFGA-outage e2e test possible without
 * disrupting the shared local OpenFGA instance other, concurrently-running
 * test files/suites depend on: that test boots a second, throwaway
 * `AgentMtlsAppModule` instance pointed at a genuinely unreachable port,
 * confirms it fails closed, and never touches the real shared container.
 */
@Injectable()
export class OpenFgaClientService implements OnModuleInit {
  private readonly logger = new Logger(OpenFgaClientService.name);
  private client: OpenFgaClient | null = null;
  /** Checks only: its HTTP timeout is the check bound, so a timed-out check never leaves its socket open. */
  private checkClient: OpenFgaClient | null = null;
  /** Spec 7.2: tuple key -> expiry (ms epoch) of a cached ALLOW. Bounded; oldest out first. */
  private readonly allowed = new Map<string, number>();
  private static readonly CACHE_MAX_ENTRIES = 10_000;
  private _storeId: string | null = null;
  private _authorizationModelId: string | null = null;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {}

  get storeId(): string | null {
    return this._storeId;
  }

  get authorizationModelId(): string | null {
    return this._authorizationModelId;
  }

  async onModuleInit(): Promise<void> {
    try {
      const apiUrl = this.configService.get('OPENFGA_API_URL', {
        infer: true,
      });
      const bootstrapClient = new OpenFgaClient({ apiUrl });

      const storeId = await this.resolveStoreId(bootstrapClient);
      const client = new OpenFgaClient({ apiUrl, storeId });
      this.client = client;
      this.checkClient = buildCheckClient(
        apiUrl,
        storeId,
        this.configService.get('OPENFGA_CHECK_TIMEOUT_MS', { infer: true }),
      );
      this._storeId = storeId;
      this._authorizationModelId =
        await this.resolveAuthorizationModelId(client);

      this.logger.log(
        `OpenFGA ready: store=${this._storeId} model=${this._authorizationModelId}`,
      );
    } catch (error) {
      this.logger.error(
        'OpenFGA store/model resolution failed at boot — every authorization check will fail closed until this resolves (never crashing the whole app over a transient OpenFGA outage)',
        error instanceof Error ? error.stack : undefined,
      );
    }
  }

  /**
   * Writes/deletes relationship tuples — see TaskGrantSyncService for the
   * only caller. `conflict.onDuplicateWrites: 'ignore'` makes this
   * idempotent: several tasks sharing the same `toolId`/`actionId`
   * (`tool`/`tool_action`/`resource` object IDs are deliberately *not*
   * task-scoped — see openfga-object-id.util.ts — they're a shared
   * vocabulary across every task that references the same tool) will
   * legitimately attempt to write the exact same supporting-graph tuple
   * more than once. OpenFGA's default (`'error'`) treats re-writing an
   * already-identical tuple as a failure; re-asserting a fact that's
   * already true is not an error condition here.
   */
  async write(input: {
    writes?: TupleKey[];
    deletes?: TupleKey[];
    /** Staff RBAC: deleting a tuple that is already gone is the desired state, not an error. */
    ignoreMissingDeletes?: boolean;
  }): Promise<void> {
    if (!input.writes?.length && !input.deletes?.length) return;
    // A revoked tuple must not be served from this process's cache.
    if (input.deletes?.length) this.allowed.clear();
    await this.requireClient().write(
      { writes: input.writes, deletes: input.deletes },
      {
        authorizationModelId: this.requireModelId(),
        conflict: {
          onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore,
          ...(input.ignoreMissingDeletes
            ? { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore }
            : {}),
        },
      },
    );
    // Again after the commit: a check that raced the write may have cached the old answer.
    if (input.deletes?.length) this.allowed.clear();
  }

  /** Every tuple on one object (staff RBAC reconciler). Throws on any failure. */
  readObject(object: string): Promise<TupleKey[]> {
    return this.readTuples({ object });
  }

  /** Tuples matching `filter` (object, optionally narrowed to one user). Throws on any failure. */
  async readTuples(filter: {
    object: string;
    user?: string;
  }): Promise<TupleKey[]> {
    const out: TupleKey[] = [];
    let continuationToken: string | undefined;
    do {
      const page = await this.requireClient().read(filter, {
        pageSize: 100,
        continuationToken,
      });
      for (const t of page.tuples)
        out.push({
          user: t.key.user,
          relation: t.key.relation,
          object: t.key.object,
          ...(t.key.condition
            ? {
                condition: {
                  name: t.key.condition.name,
                  context: t.key.condition.context as Record<string, unknown>,
                },
              }
            : {}),
        });
      continuationToken = page.continuation_token || undefined;
    } while (continuationToken);
    return out;
  }

  /** A single relationship check — throws on any transport/server failure, deliberately not swallowed here (see class doc comment). */
  async check(
    tuple: TupleKey,
    options?: { consistency?: 'high'; context?: Record<string, unknown> },
  ): Promise<boolean> {
    // Spec 7.2: only ALLOW is reused, for at most OPENFGA_CACHE_TTL_MS; `high` always asks OpenFGA.
    // A conditional check (staff RBAC passes `current_time`) is never cached: its answer depends
    // on the context, and an elevation must end at its expiry (DESK AC-30).
    const ttlMs =
      this.configService.get('OPENFGA_CACHE_TTL_MS', { infer: true }) ?? 3000;
    const useCache =
      ttlMs > 0 && options?.consistency !== 'high' && !options?.context;
    const key = `${tuple.user}|${tuple.relation}|${tuple.object}`;
    if (useCache) {
      const expiresAt = this.allowed.get(key);
      if (expiresAt !== undefined && performance.now() <= expiresAt)
        return true;
      this.allowed.delete(key);
    }
    const allowed = await this.checkRemote(tuple, options?.context);
    if (allowed && useCache) {
      this.allowed.set(key, performance.now() + ttlMs);
      if (this.allowed.size > OpenFgaClientService.CACHE_MAX_ENTRIES) {
        const oldest = this.allowed.keys().next().value;
        if (oldest !== undefined) this.allowed.delete(oldest);
      }
    }
    return allowed;
  }

  private async checkRemote(
    tuple: TupleKey,
    context?: Record<string, unknown>,
  ): Promise<boolean> {
    const timeoutMs = this.configService.get('OPENFGA_CHECK_TIMEOUT_MS', {
      infer: true,
    });
    let timer: NodeJS.Timeout | undefined;
    try {
      const result = await Promise.race([
        this.requireCheckClient().check(
          context ? { ...tuple, context } : tuple,
          {
            authorizationModelId: this.requireModelId(),
            // One quick retry for a blip; the race below bounds the total.
            retryParams: { maxRetry: 1, minWaitInMs: 50 },
          },
        ),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new Error(`OpenFGA check timed out after ${timeoutMs} ms`),
              ),
            timeoutMs,
          );
        }),
      ]);
      return result.allowed ?? false;
    } finally {
      clearTimeout(timer);
    }
  }

  private requireCheckClient(): OpenFgaClient {
    if (!this.checkClient) return this.requireClient();
    return this.checkClient;
  }

  private requireClient(): OpenFgaClient {
    if (!this.client) {
      throw new Error(
        'OpenFgaClientService has no working OpenFGA client (store/model resolution failed or has not completed yet)',
      );
    }
    return this.client;
  }

  private requireModelId(): string {
    if (!this._authorizationModelId) {
      throw new Error(
        'OpenFgaClientService has no resolved authorization model ID',
      );
    }
    return this._authorizationModelId;
  }

  private async resolveStoreId(client: OpenFgaClient): Promise<string> {
    const pinned = this.configService.get('OPENFGA_STORE_ID', {
      infer: true,
    });
    if (pinned) return pinned;

    const storeName = this.configService.get('OPENFGA_STORE_NAME', {
      infer: true,
    });

    let continuationToken: string | undefined;
    do {
      const page = await client.listStores({
        pageSize: 100,
        continuationToken,
      });
      const existing = page.stores.find((store) => store.name === storeName);
      if (existing) return existing.id;
      continuationToken = page.continuation_token || undefined;
    } while (continuationToken);

    this.logger.log(`Creating OpenFGA store "${storeName}" (none found)`);
    const created = await client.createStore({ name: storeName });
    return created.id;
  }

  /**
   * Reuses the store's latest authorization model if it already matches
   * this process's DSL file exactly (comparing the transformed type
   * definitions, not just presence), otherwise writes a new model version.
   * OpenFGA model versions are immutable and purely additive — writing one
   * that turns out to be identical to the last would be harmless but
   * wasteful (and would churn `authorizationModelId` on every boot in
   * local dev with no schema change), so this comparison avoids that.
   */
  private async resolveAuthorizationModelId(
    client: OpenFgaClient,
  ): Promise<string> {
    const pinned = this.configService.get('OPENFGA_AUTHORIZATION_MODEL_ID', {
      infer: true,
    });
    if (pinned) return pinned;

    const modelFilePath = this.configService.get('OPENFGA_MODEL_FILE_PATH', {
      infer: true,
    });
    const dsl = readFileSync(modelFilePath, 'utf8');
    const desired = transformer.transformDSLToJSONObject(dsl) as {
      schema_version: string;
      type_definitions: TypeDefinition[];
      conditions?: Record<string, Condition>;
    };

    const latest = await client
      .readLatestAuthorizationModel()
      .catch(() => null);

    if (
      latest?.authorization_model &&
      sameModel(
        latest.authorization_model.type_definitions,
        desired.type_definitions,
      ) &&
      sameConditions(latest.authorization_model.conditions, desired.conditions)
    ) {
      return latest.authorization_model.id;
    }

    this.logger.log('Writing a new OpenFGA authorization model version');
    const written = await client.writeAuthorizationModel(desired);
    return written.authorization_model_id;
  }
}

/** Order-insensitive deep comparison of two type-definition arrays — good enough to detect "the DSL file changed" without pulling in a generic deep-equal dependency. */
function sameModel(a: TypeDefinition[], b: TypeDefinition[]): boolean {
  const normalize = (defs: TypeDefinition[]) =>
    JSON.stringify([...defs].sort((x, y) => x.type.localeCompare(y.type)));
  return normalize(a) === normalize(b);
}

/** A model whose conditions changed is a new model, even with the same types. */
export function sameConditions(a: unknown, b: unknown): boolean {
  const keys = (v: unknown) =>
    JSON.stringify(Object.keys((v as object | undefined) ?? {}).sort());
  return keys(a) === keys(b);
}

/**
 * An OpenFGA client for checks whose HTTP timeout equals the check bound
 * (OPENFGA_CHECK_TIMEOUT_MS): the SDK's default is 10 s, so during an outage
 * every timed-out check would otherwise hold a socket for 10 s and pile up.
 */
export function buildCheckClient(
  apiUrl: string,
  storeId: string,
  timeoutMs: number,
): OpenFgaClient {
  return new OpenFgaClient(
    { apiUrl, storeId },
    axios.create({
      httpAgent: new HttpAgent({ keepAlive: true }),
      httpsAgent: new HttpsAgent({ keepAlive: true }),
      timeout: timeoutMs,
    }),
  );
}
