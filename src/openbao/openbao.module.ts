import { Global, Module } from '@nestjs/common';
import { OpenBaoPkiClient } from './openbao-pki.client';

/**
 * Wires up the OpenBao PKI HTTP client. Global for the same reason
 * `DatabaseModule`/`AuthModule` are — `CertificateAuthorityService` (and
 * anything else needing PKI operations) is a cross-cutting dependency, not
 * scoped to one feature module.
 */
@Global()
@Module({
  providers: [OpenBaoPkiClient],
  exports: [OpenBaoPkiClient],
})
export class OpenBaoModule {}
