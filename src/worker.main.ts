import 'dotenv/config';
import { NativeConnection, Worker } from '@temporalio/worker';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';
import { WorkerAppModule } from './temporal/worker-app.module';
import { ApprovalActivitiesFactory } from './temporal/activities/approval.activities';
import { AuditRetentionActivitiesFactory } from './temporal/activities/audit-retention.activities';
import { WebhookDeliveryActivitiesFactory } from './temporal/activities/webhook-delivery.activities';
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

  // Signal handling is installed here, the instant the DI container exists
  // and *before* the (potentially slow) Temporal connect and worker
  // construction below. A SIGTERM during startup — routine during a
  // rollout, a node drain, or a failing readiness gate on the API pods
  // restarting the whole namespace — previously hit Node's default handler
  // and killed the process outright, with every Prisma/Kafka/Redis
  // connection this container had already opened left dangling server-side.

  // Assigned at the bottom of this function, after the Temporal connect,
  // but read by the onSignal closure below; a const cannot be declared
  // here and populated there.
  // eslint-disable-next-line prefer-const
  let drainWorkers: (() => void) | undefined;
  let shuttingDown = false;
  const onSignal = (signal: NodeJS.Signals): void => {
    // Repeat signals during an in-progress drain are ignored, not escalated
    // — an operator's second Ctrl-C should not abort the cleanup the first
    // one started.
    if (shuttingDown) return;
    shuttingDown = true;

    if (drainWorkers) {
      logger.log(`Received ${signal}; draining Temporal workers...`);
      drainWorkers();
      return;
    }

    // Startup was interrupted before either Worker began polling, so there
    // is nothing to drain and nothing in flight to lose — release the DI
    // container's connections and exit. `process.exit` is deliberate here
    // (and only here): the half-built `NativeConnection.connect` in
    // progress above would otherwise keep the event loop alive with no
    // worker left to service it.
    logger.log(`Received ${signal} during startup; closing without draining`);
    void closeQuietly(logger, 'Nest application context', () =>
      appContext.close(),
    ).then(() => process.exit(0));
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  const configService = appContext.get(ConfigService<AppConfig, true>);
  const address = configService.get('TEMPORAL_ADDRESS', { infer: true });
  const namespace = configService.get('TEMPORAL_NAMESPACE', { infer: true });
  const taskQueue = configService.get('TEMPORAL_TASK_QUEUE', { infer: true });
  const webhookTaskQueue = configService.get('WEBHOOK_DELIVERY_TASK_QUEUE', {
    infer: true,
  });

  const activities = {
    ...appContext.get(ApprovalActivitiesFactory).build(),
    ...appContext.get(AuditRetentionActivitiesFactory).build(),
    ...appContext.get(WebhookDeliveryActivitiesFactory).build(),
  };

  const connection = await NativeConnection.connect({ address });

  // Resolves to this same directory's compiled workflow *bundle*
  // (`dist/temporal/workflows/index.js` in a built image, the tsc-compiled
  // equivalent under dev — `nest start`/`nest build` both compile via tsc,
  // never webpack, for this project — see nest-cli.json). Re-exports every
  // workflow this codebase has (`ApprovalWorkflow`, `AuditRetentionWorkflow`,
  // `WebhookDeliveryWorkflow`) — see `src/temporal/workflows/index.ts`'s
  // doc comment.
  const workflowsPath = require.resolve('./temporal/workflows/index');

  const approvalsWorker = await Worker.create({
    connection,
    namespace,
    taskQueue,
    workflowsPath,
    activities,
  });

  // A second `Worker` on `WEBHOOK_DELIVERY_TASK_QUEUE`, same connection/
  // activities/bundle as above -- still one process, not a general "a
  // queue per workflow" pattern (see that config field's own doc comment,
  // `src/webhooks/webhooks.config.ts`, for exactly why webhook delivery
  // alone needs a queue separate from `TEMPORAL_TASK_QUEUE`).
  const webhooksWorker = await Worker.create({
    connection,
    namespace,
    taskQueue: webhookTaskQueue,
    workflowsPath,
    activities,
  });

  logger.log(
    `Temporal worker starting: address="${address}" namespace="${namespace}" taskQueues=["${taskQueue}", "${webhookTaskQueue}"]`,
  );

  // From here on a signal drains the task queues rather than aborting
  // startup — see `onSignal` above.
  drainWorkers = (): void => {
    approvalsWorker.shutdown();
    webhooksWorker.shutdown();
  };

  try {
    await Promise.all([approvalsWorker.run(), webhooksWorker.run()]);
  } finally {
    // Release 2026-11-11 reliability fix. `appContext.close()` is what runs
    // every provider's `onModuleDestroy` — `TenantDatabaseManager`'s cached
    // per-tenant Prisma clients (each a real Postgres connection pool),
    // `ControlPrismaService`, `KafkaPublisherService`'s producer, the Redis
    // clients. Before this release nothing guaranteed it ever ran: a
    // `Worker.run()` that *rejected* (a broker error, a bad workflow
    // bundle) propagated straight out of `bootstrap`, and `void bootstrap()`
    // turned that into an unhandled rejection that killed the process with
    // every one of those connections still open server-side.
    //
    // Deliberately NOT `appContext.enableShutdownHooks()`, which is the
    // right tool for the HTTP processes (`src/main.ts`) but the wrong one
    // here: Nest's hook closes the DI container and then re-raises the
    // signal to terminate the process, which would race the Temporal
    // drain above and kill in-flight Activities mid-execution — the exact
    // opposite of graceful for a workflow runtime. Draining first and
    // closing the container afterwards, as below, is the correct order.
    await closeQuietly(logger, 'Temporal connection', () => connection.close());
    await closeQuietly(logger, 'Nest application context', () =>
      appContext.close(),
    );
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    logger.log('Temporal worker shutdown complete');
  }
}

/**
 * Runs one shutdown step, logging and swallowing any failure.
 *
 * Shutdown steps must not be able to abort each other: if closing the
 * Temporal connection throws, the DI container — holding the database and
 * Kafka connections this whole fix exists to release — still has to be
 * closed. A failure here is worth knowing about but is never worth leaking
 * a connection pool over.
 */
async function closeQuietly(
  logger: Logger,
  what: string,
  close: () => Promise<void>,
): Promise<void> {
  try {
    await close();
  } catch (error) {
    logger.error(
      `Failed to close ${what} during shutdown: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

bootstrap().catch((error: unknown) => {
  // A rejected bootstrap used to be an unhandled rejection (`void
  // bootstrap()`), which under Node's default policy kills the process with
  // a stack trace and no exit-code contract. Log it and exit non-zero so a
  // crash-looping worker is legible in `kubectl logs`/pod status rather
  // than just gone.
  new Logger('WorkerBootstrap').error(
    `Temporal worker failed to start: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
  );
  process.exitCode = 1;
});
