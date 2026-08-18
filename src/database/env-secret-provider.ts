import { Injectable } from '@nestjs/common';
import { SecretProvider, SecretReferenceDescriptor } from './secret-provider';

/**
 * Resolves a `SecretReference` with `provider: 'ENV'` by reading the named
 * environment variable directly.
 *
 * This is a deliberate, documented exception to the "only the config
 * module reads `process.env`" rule (`src/config/config.module.ts`): the
 * variable *name* here is data (`SecretReference.reference`, an opaque
 * string chosen at provisioning time), not a fixed key `AppConfigSchema`
 * can declare ahead of time — Zod validation can't express "some
 * dynamically-named key exists." `OpenBaoSecretProvider` (Phase 4/17) will
 * face the same shape of problem against a real secret store, which is
 * exactly why this lives behind the `SecretProvider` interface instead of
 * being inlined into `TenantDatabaseManager`.
 */
@Injectable()
export class EnvSecretProvider implements SecretProvider {
  // Not `async`: nothing here awaits, and resolution is intentionally
  // synchronous — `Promise.resolve` still satisfies the `SecretProvider`
  // interface's async contract that `OpenBaoSecretProvider` (Phase 4/17)
  // will genuinely need.
  resolve(ref: SecretReferenceDescriptor): Promise<string> {
    if (ref.provider !== 'ENV') {
      throw new Error(
        `EnvSecretProvider cannot resolve a "${ref.provider}" secret reference (only "ENV" is supported this phase)`,
      );
    }

    const value = process.env[ref.reference];
    if (!value) {
      throw new Error(
        `Environment variable "${ref.reference}" (named by a SecretReference) is not set`,
      );
    }

    return Promise.resolve(value);
  }
}
