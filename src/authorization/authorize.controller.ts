import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { AuthorizeRequestSchema } from './authorize-request.validation';
import { AuthorizationService } from './authorization.service';

/**
 * `POST /agent/v1/authorize` — mTLS-gated (Phase 4's `AgentMtlsGuard`), the
 * only entry point into `AuthorizationService`'s 6-step pipeline. Always
 * responds 200/201 with `{ decision: 'ALLOW' }` or `{ decision: 'DENY',
 * reason }` for a well-formed request against a real caller — a DENY is a
 * legitimate, expected answer from a policy-decision-point endpoint, not
 * an HTTP-level error, so it never maps to a 403/404 (which would leak
 * *why* through the HTTP status code alone, on top of the returned
 * `reason` — a caller should learn the reason exactly once, from the body,
 * not twice from two different signals). Malformed request bodies still
 * 400 via `parseBodyOrThrow`, same as every other validated endpoint.
 */
@Controller('agent/v1')
export class AuthorizeController {
  constructor(
    private readonly authorizationService: AuthorizationService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post('authorize')
  @UseGuards(AgentMtlsGuard)
  async authorize(@CurrentAgent() agent: AgentContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(AuthorizeRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      agent.tenant.id,
    );

    return this.authorizationService.authorize(
      tenantClient,
      agent.tenant.id,
      agent.agent.id,
      input,
    );
  }
}
