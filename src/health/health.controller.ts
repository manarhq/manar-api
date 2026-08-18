import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';

export interface HealthStatus {
  status: 'ok';
}

@Controller('health')
export class HealthController {
  /**
   * Process liveness: the HTTP server is up and answering requests.
   * Always 200 once the process has started — no dependency checks here.
   */
  @Get('live')
  @HttpCode(HttpStatus.OK)
  live(): HealthStatus {
    return { status: 'ok' };
  }

  /**
   * Readiness stub. This phase has no downstream dependencies (DB, cache,
   * queue, etc.) to actually check yet, so this intentionally always
   * reports ready rather than faking a check that doesn't exist. Later
   * phases should extend this handler with real dependency checks instead
   * of adding a second endpoint.
   */
  @Get('ready')
  @HttpCode(HttpStatus.OK)
  ready(): HealthStatus {
    return { status: 'ok' };
  }
}
