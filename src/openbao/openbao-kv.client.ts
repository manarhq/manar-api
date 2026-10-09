import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/env.validation';

/**
 * Thin wrapper around OpenBao's KV v2 secrets engine HTTP API
 * (https://openbao.org/docs/secrets/kv/kv-v2/), covering exactly what
 * `OpenBaoSecretProvider` needs: read and write a secret at a logical path
 * under this deployment's KV mount (`OPENBAO_KV_MOUNT_PATH`).
 *
 * A separate, narrowly-scoped client from `OpenBaoPkiClient` — same
 * reasoning `CertificateAuthorityService`/`OpenBaoPkiClient` already
 * establish for PKI (a small, single-purpose wrapper per OpenBao secrets
 * engine, not one do-everything client) — deliberately does not share a
 * base class with it for the sake of ~15 lines of near-identical `fetch`
 * plumbing; each engine's request/response shape differs enough (PKI's
 * `sign-verbatim`/`revoke` vs. KV v2's `data`-wrapped read/write) that a
 * shared abstraction would buy little.
 *
 * Authenticates with the same deployment-wide bootstrap token
 * (`OPENBAO_TOKEN`) as `OpenBaoPkiClient` — see that class's doc comment
 * for why this mirrors `KeycloakAdminClient`'s bootstrap-admin pattern
 * rather than a per-tenant credential.
 */
@Injectable()
export class OpenBaoKvClient {
  private readonly logger = new Logger(OpenBaoKvClient.name);
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly mountPath: string;

  constructor(configService: ConfigService<AppConfig, true>) {
    this.baseUrl = configService.get('OPENBAO_ADDR', { infer: true });
    this.token = configService.get('OPENBAO_TOKEN', { infer: true });
    this.mountPath = configService.get('OPENBAO_KV_MOUNT_PATH', {
      infer: true,
    });
  }

  /**
   * Reads the current (latest) version of the KV v2 secret at `path`
   * (relative to the mount — e.g. `tools/soc-fixture`, never including the
   * `data/` API-path segment or the mount name itself). Returns the raw
   * `data` object stored at that path — `OpenBaoSecretProvider` is
   * responsible for picking a specific key out of it. Throws if the path
   * has no secret (or no current, non-deleted version).
   */
  async readSecret(path: string): Promise<Record<string, unknown>> {
    const response = await this.request<{
      data: Record<string, unknown>;
      metadata: { version: number; deletion_time?: string };
    }>('GET', `${this.mountPath}/data/${path}`);

    if (response.metadata?.deletion_time) {
      throw new Error(
        `OpenBao KV secret at "${path}" has been deleted (version ${response.metadata.version})`,
      );
    }

    return response.data;
  }

  /**
   * Writes a new version of the KV v2 secret at `path`, replacing whatever
   * `data` object was previously stored there (KV v2 versions the whole
   * object per write, not per key — see the design's docs/tool-gateway.md
   * for why this is fine for this phase's "one opaque credential value per
   * reference" convention). Used only by this phase's own test fixtures
   * and any future seeding tooling — `OpenBaoSecretProvider` itself only
   * ever reads.
   */
  async writeSecret(
    path: string,
    data: Record<string, unknown>,
  ): Promise<void> {
    await this.request('POST', `${this.mountPath}/data/${path}`, { data });
  }

  /**
   * KV v1 (no versions, delete is permanent), for values that must not
   * survive their deletion, such as an approval handover (ADR-0011). `path`
   * includes the mount, e.g. `handover/<tenant>/<id>`. Reads and lists
   * return `null` for a missing path; any other failure throws.
   */
  async readV1(path: string): Promise<Record<string, unknown> | null> {
    return this.request<Record<string, unknown>>('GET', path, undefined, true);
  }

  async writeV1(path: string, data: Record<string, unknown>): Promise<void> {
    await this.request('POST', path, data);
  }

  async deleteV1(path: string): Promise<void> {
    await this.request('DELETE', path);
  }

  async listV1(path: string): Promise<string[]> {
    const data = await this.request<{ keys?: string[] }>(
      'GET',
      `${path}?list=true`,
      undefined,
      true,
    );
    return data?.keys ?? [];
  }

  private async request<T>(
    method: 'GET' | 'POST' | 'DELETE',
    apiPath: string,
    body?: unknown,
    nullOn404 = false,
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}/v1/${apiPath}`, {
      method,
      headers: {
        'X-Vault-Token': this.token,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (nullOn404 && response.status === 404) {
      await response.body?.cancel();
      return null as T;
    }
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      this.logger.error(
        `OpenBao KV API ${method} ${apiPath} failed: HTTP ${response.status}`,
      );
      // Deliberately does not include the request body in the thrown
      // error — for a write, that body is the secret value itself.
      throw new Error(
        `OpenBao KV API ${method} ${apiPath} failed with HTTP ${response.status}${
          text ? `: ${text}` : ''
        }`,
      );
    }

    if (response.status === 204) return undefined as T;
    const json = (await response.json()) as { data: T };
    return json.data;
  }
}
