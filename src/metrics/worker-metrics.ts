import type { Logger } from '@nestjs/common';
import { Runtime } from '@temporalio/worker';

/**
 * Temporal's own Prometheus exporter for the worker (task latency, slots,
 * polls) on WORKER_METRICS_PORT. Must run before the first connection
 * creates the Runtime. A port already in use is logged and the worker
 * starts without metrics, like the API's metrics listener: losing metrics
 * never stops approvals. Returns whether the exporter is running.
 */
export function installWorkerMetrics(port: number, logger: Logger): boolean {
  if (port === 0) return false;
  try {
    Runtime.install({
      telemetryOptions: {
        metrics: {
          // Replaces core's own service_name="temporal-core-sdk" (two
          // service_name labels would make the scrape invalid).
          attachServiceName: false,
          globalTags: { service_name: 'manar-api-worker' },
          prometheus: {
            bindAddress: `0.0.0.0:${port}`,
            useSecondsForDurations: true,
          },
        },
      },
    });
    return true;
  } catch (error) {
    logger.error(
      `worker metrics listener on :${port} failed, continuing without metrics: ${error instanceof Error ? error.message : String(error)}`,
    );
    return false;
  }
}
