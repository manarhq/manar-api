import { readFileSync } from 'node:fs';
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OpenFgaClient, type TypeDefinition } from '@openfga/sdk';
import { transformer } from '@openfga/syntax-transformer';
import { AppConfig } from '../config/env.validation';

export interface TupleKey {
  user: string;
  relation: string;
  object: string;
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
 * throws it. `AuthorizationService` is where the fail-closed *policy*
 * decision belongs (Section 22: if any check can't be evaluated
 * trustworthily, DENY) — this service's job is only to make the call
 * honestly, never to silently swallow a failure into an ambiguous result.
 */
@Injectable()
export class OpenFgaClientService implements OnModuleInit {
  private readonly logger = new Logger(OpenFgaClientService.name);
  private client!: OpenFgaClient;
  private _storeId!: string;
  private _authorizationModelId!: string;

  constructor(private readonly configService: ConfigService<AppConfig, true>) {}

  get storeId(): string {
    return this._storeId;
  }

  get authorizationModelId(): string {
    return this._authorizationModelId;
  }

  async onModuleInit(): Promise<void> {
    const apiUrl = this.configService.get('OPENFGA_API_URL', { infer: true });
    const bootstrapClient = new OpenFgaClient({ apiUrl });

    this._storeId = await this.resolveStoreId(bootstrapClient);
    this.client = new OpenFgaClient({ apiUrl, storeId: this._storeId });
    this._authorizationModelId = await this.resolveAuthorizationModelId();

    this.logger.log(
      `OpenFGA ready: store=${this._storeId} model=${this._authorizationModelId}`,
    );
  }

  /** Writes/deletes relationship tuples — see TaskGrantSyncService for the only caller. */
  async write(input: {
    writes?: TupleKey[];
    deletes?: TupleKey[];
  }): Promise<void> {
    if (!input.writes?.length && !input.deletes?.length) return;
    await this.client.write(
      { writes: input.writes, deletes: input.deletes },
      { authorizationModelId: this._authorizationModelId },
    );
  }

  /** A single relationship check — throws on any transport/server failure, deliberately not swallowed here (see class doc comment). */
  async check(tuple: TupleKey): Promise<boolean> {
    const result = await this.client.check(tuple, {
      authorizationModelId: this._authorizationModelId,
    });
    return result.allowed ?? false;
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
  private async resolveAuthorizationModelId(): Promise<string> {
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
    };

    const latest = await this.client
      .readLatestAuthorizationModel()
      .catch(() => null);

    if (
      latest?.authorization_model &&
      sameModel(
        latest.authorization_model.type_definitions,
        desired.type_definitions,
      )
    ) {
      return latest.authorization_model.id;
    }

    this.logger.log('Writing a new OpenFGA authorization model version');
    const written = await this.client.writeAuthorizationModel(desired);
    return written.authorization_model_id;
  }
}

/** Order-insensitive deep comparison of two type-definition arrays — good enough to detect "the DSL file changed" without pulling in a generic deep-equal dependency. */
function sameModel(a: TypeDefinition[], b: TypeDefinition[]): boolean {
  const normalize = (defs: TypeDefinition[]) =>
    JSON.stringify([...defs].sort((x, y) => x.type.localeCompare(y.type)));
  return normalize(a) === normalize(b);
}
