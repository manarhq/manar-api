import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  ServiceUnavailableException,
} from '@nestjs/common';
import { HEALTH_ROUTE_PREFIX } from './health.routes';
import { ReadinessService } from './readiness.service';
import type { ReadinessReport } from './readiness';

export interface HealthStatus {
  status: 'ok';
}

@Controller(HEALTH_ROUTE_PREFIX)
export class HealthController {
  constructor(private readonly readinessService: ReadinessService) {}

  /**
   * Process liveness: the HTTP server is up and answering requests.
   * Always 200 once the process has started — no dependency checks here,
   * and deliberately so.
   *
   * A liveness failure means "kill this container", so anything this
   * handler touches becomes something a kubelet will restart every replica
   * over. That is the entire reason this stays a constant: it answers "is
   * this event loop still turning", nothing else. "Is the database up" is
   * `/health/ready`'s question, and its answer is to stop taking traffic —
   * not to die.
   *
   * `TenantThrottlerGuard` explicitly exempts this route from rate limiting
   * (see its `shouldSkip`); before that exemption existed, a Redis outage
   * made this endpoint 500 and restarted the entire Deployment.
   */
  @Get('live')
  @HttpCode(HttpStatus.OK)
  live(): HealthStatus {
    return { status: 'ok' };
  }

  /**
   * Dependency-aware readiness: should this replica be in the Service's
   * endpoint list right now?
   *
   * Returns the full per-dependency report either way — 200 when `ready`
   * (including the `degraded` case, where every *required* dependency is
   * healthy and some optional one is not), 503 when a required dependency
   * is unhealthy or its probe timed out. The kubelet only reads the status
   * code; the body is for whoever is looking at the pod during an incident,
   * which is why a 503 carries the same structure as a 200 rather than a
   * bare error.
   *
   * `ReadinessService` owns which dependencies are required and why — the
   * short version being that almost none are, because every replica shares
   * every dependency, so an over-eager required flag turns one dependency's
   * outage into a total outage.
   */
  @Get('ready')
  @HttpCode(HttpStatus.OK)
  async ready(): Promise<ReadinessReport> {
    const report = await this.readinessService.check();
    if (!report.ready) {
      // The exception's object argument becomes the response body verbatim,
      // so the 503 carries the same per-dependency detail a 200 does.
      throw new ServiceUnavailableException(report);
    }
    return report;
  }
}
