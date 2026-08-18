import { Global, Module } from '@nestjs/common';
import { OpenFgaClientService } from './openfga-client.service';
import { TaskGrantSyncService } from './task-grant-sync.service';

/**
 * Providers-only (no controllers) — this module's job is exclusively "own
 * the OpenFGA client and know how to mirror a task's grants into it",
 * shared by both Nest applications: the human-facing `AppModule` (task
 * creation writes tuples) and the agent-facing `AgentMtlsAppModule`
 * (delegation writes a child task's tuples; `AuthorizationService`, in its
 * own module, reads via `OpenFgaClientService.check`). Deliberately kept
 * free of any controller so it can be imported into both apps' module
 * graphs without exposing any route on either — see
 * `src/agents/agents.module.ts`'s doc comment for the same
 * services-only/controllers-elsewhere split, applied here from the start
 * rather than retrofitted.
 *
 * `@Global()` for the same reason `DatabaseModule`/`OpenBaoModule` are —
 * cross-cutting infrastructure every future authorization-adjacent module
 * depends on. Global only scopes within whichever single app imports it,
 * so both `app.module.ts` and `agent-mtls-app.module.ts` import this
 * explicitly.
 */
@Global()
@Module({
  providers: [OpenFgaClientService, TaskGrantSyncService],
  exports: [OpenFgaClientService, TaskGrantSyncService],
})
export class AuthorizationModule {}
