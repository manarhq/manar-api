import { Global, Module } from '@nestjs/common';
import { OpenBaoKvClient } from './openbao-kv.client';
import { OpenBaoPkiClient } from './openbao-pki.client';

/**
 * Wires up the OpenBao PKI and KV v2 HTTP clients. Global for the same
 * reason `DatabaseModule`/`AuthModule` are — `CertificateAuthorityService`
 * (PKI) and `OpenBaoSecretProvider` (Phase 7b, KV v2 — see
 * `src/database/openbao-secret-provider.ts`) are cross-cutting
 * dependencies, not scoped to one feature module.
 */
@Global()
@Module({
  providers: [OpenBaoPkiClient, OpenBaoKvClient],
  exports: [OpenBaoPkiClient, OpenBaoKvClient],
})
export class OpenBaoModule {}
