import { Injectable } from '@nestjs/common';
import { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import { SecretProvider, SecretReferenceDescriptor } from './secret-provider';

/**
 * Resolves a `SecretReference`/`SecretReferenceDescriptor` with
 * `provider: 'OPENBAO'` against OpenBao's KV v2 secrets engine
 * (`OpenBaoKvClient`) — the implementation `docs/agent-identity.md` and
 * `env-secret-provider.ts` both said was coming. `reference` is the KV v2
 * secret's logical path (relative to `OPENBAO_KV_MOUNT_PATH`, e.g.
 * `tools/soc-fixture`) — this class owns exactly one convention on top of
 * the raw KV object `OpenBaoKvClient` returns: the credential value itself
 * is always stored under the fixed key `"value"` (mirroring
 * `EnvSecretProvider`'s "one opaque string per reference" shape, so
 * `CredentialBrokerService` never needs to know or care which provider a
 * given `Tool.credentialReference` actually names — see that service's own
 * doc comment).
 *
 * Manar owns this convention; OpenBao's KV v2 engine itself has no opinion
 * about what keys a secret's `data` object contains — the same
 * "Manar-owned policy, external system only does the mechanical operation"
 * shape `CertificateAuthorityService`/`OpenBaoPkiClient` establish for PKI,
 * just with much less policy to own here (there is no CSR/subject to
 * validate for a plain credential read).
 */
@Injectable()
export class OpenBaoSecretProvider implements SecretProvider {
  /** The fixed key `OpenBaoKvClient.readSecret`'s `data` object stores a tool credential's value under. */
  static readonly CREDENTIAL_KEY = 'value';

  constructor(private readonly kv: OpenBaoKvClient) {}

  async resolve(ref: SecretReferenceDescriptor): Promise<string> {
    if (ref.provider !== 'OPENBAO') {
      throw new Error(
        `OpenBaoSecretProvider cannot resolve a "${ref.provider}" secret reference (only "OPENBAO" is supported)`,
      );
    }

    const data = await this.kv.readSecret(ref.reference);
    const value = data[OpenBaoSecretProvider.CREDENTIAL_KEY];
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(
        `OpenBao KV secret at "${ref.reference}" has no non-empty string "${OpenBaoSecretProvider.CREDENTIAL_KEY}" field`,
      );
    }

    return value;
  }
}
