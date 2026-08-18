import 'dotenv/config';
import { NativeConnection, Worker } from '@temporalio/worker';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';
import { WorkerAppModule } from './temporal/worker-app.module';
import { ApprovalActivitiesFactory } from './temporal/activities/approval.activities';
import type { AppConfig } from './config/env.validation';

/**
 * Entry point for the separate Temporal worker process (Section 28: the
 * workflow runtime — and every Activity it calls — never shares an event
 * loop with the Fastify HTTP server `src/main.ts` bootstraps). Run via
 * `pnpm worker` (dev) or `node dist/worker.main.js`/`pnpm worker:prod`
 * (the Dockerfile's `worker` stage — see that file). See
 * docs/approvals.md.
 *
 * Bootstraps a plain Nest *application context* (no HTTP listener at all —
 * `WorkerAppModule` imports no controller-bearing module) purely to obtain
 * real, DI-wired provider instances (`TenantDatabaseManager`,
 * `PolicyEngine`, `RiskEngine`, `GrantService`, ...) — the exact same ones
 * the HTTP processes use, via `ApprovalActivitiesFactory` — then hands
 * those off to a `@temporalio/worker` `Worker`, which polls
 * `TEMPORAL_TASK_QUEUE` and executes `ApprovalWorkflow` (bundled fresh
 * from its own compiled file — see `workflowsPath` below, which resolves
 * to the file with only `import type` references to
 * `approval.activities.ts`, so none of this file's own Nest/Prisma/crypto
 * code is ever pulled into the workflow's deterministic sandbox) plus its
 * Activities (this process's own real, non-sandboxed code — free to do
 * I/O, unlike workflow code).
 */
async function bootstrap(): Promise<void> {
  const logger = new Logger('WorkerBootstrap');

  // No `bufferLogs: true` here (unlike src/main.ts's two HTTP apps) --
  // this process never calls `app.useLogger(...)` to flush a buffer (it
  // doesn't wire up the Winston logger `LoggingModule` provides; this is a
  // deliberately minimal application context, no HTTP middleware at all —
  // see WorkerAppModule's own doc comment), so buffering would silently
  // swallow every log line, including this bootstrap function's own,
  // forever.
  const appContext =
    await NestFactory.createApplicationContext(WorkerAppModule);

  const configService = appContext.get(ConfigService<AppConfig, true>);
  const address = configService.get('TEMPORAL_ADDRESS', { infer: true });
  const namespace = configService.get('TEMPORAL_NAMESPACE', { infer: true });
  const taskQueue = configService.get('TEMPORAL_TASK_QUEUE', { infer: true });

  const activities = appContext.get(ApprovalActivitiesFactory).build();

  const connection = await NativeConnection.connect({ address });

  const worker = await Worker.create({
    connection,
    namespace,
    taskQueue,
    // Resolves to this same directory's compiled workflow module
    // (`dist/temporal/workflows/approval.workflow.js` in a built image,
    // the tsc-compiled equivalent under dev — `nest start`/`nest build`
    // both compile via tsc, never webpack, for this project — see
    // nest-cli.json). Temporal's own Worker bundles whatever this path
    // resolves to into an isolated deterministic sandbox itself; it does
    // not matter whether the path is TS or JS source.
    workflowsPath: require.resolve('./temporal/workflows/approval.workflow'),
    activities,
  });

  logger.log(
    `Temporal worker starting: address="${address}" namespace="${namespace}" taskQueue="${taskQueue}"`,
  );

  const shutdown = (): void => {
    logger.log('Shutting down Temporal worker...');
    worker.shutdown();
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);

  try {
    await worker.run();
  } finally {
    await connection.close();
    await appContext.close();
  }
}

void bootstrap();
