import { Injectable } from '@nestjs/common';
import { EnvSecretProvider } from './env-secret-provider';
import { OpenBaoSecretProvider } from './openbao-secret-provider';
import { SecretProvider, SecretReferenceDescriptor } from './secret-provider';

/**
 * The `SecretProvider` bound to the `SECRET_PROVIDER` DI token
 * (`DatabaseModule`) — dispatches `resolve()` to whichever concrete
 * provider a given `SecretReferenceDescriptor.provider` actually names.
 * This is what makes `secret-provider.ts`'s "callers never know or care
 * which backend actually held it" true in practice once more than one
 * provider is implemented (Phase 7b adds the second, `OpenBaoSecretProvider`):
 * `TenantDatabaseManager` still only ever passes `ENV` references (tenant
 * DB credentials are provisioned that way this phase — unchanged), while
 * `CredentialBrokerService` may resolve either `ENV`- or `OPENBAO`-backed
 * `Tool.credentialReference`s through this exact same injected
 * `SecretProvider`, with no branching of its own.
 */
@Injectable()
export class CompositeSecretProvider implements SecretProvider {
  constructor(
    private readonly env: EnvSecretProvider,
    private readonly openBao: OpenBaoSecretProvider,
  ) {}

  // Async so an unrecognized `ref.provider` rejects the returned Promise
  // rather than throwing synchronously — callers uniformly `await`/`.catch`
  // this method regardless of which branch below actually runs.
  async resolve(ref: SecretReferenceDescriptor): Promise<string> {
    switch (ref.provider) {
      case 'ENV':
        return this.env.resolve(ref);
      case 'OPENBAO':
        return this.openBao.resolve(ref);
      default:
        throw new Error(
          `No SecretProvider implementation is wired up for provider "${ref.provider}"`,
        );
    }
  }
}
