import {
  Body,
  Controller,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { AuthorizationService } from '../authorization/authorization.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  ToolActionNotFoundError,
  ToolDisabledError,
  ToolNotFoundError,
} from './credential-broker.errors';
import { CredentialBrokerService } from './credential-broker.service';
import { ToolInvokeRequestSchema } from './tool-invoke.validation';

/**
 * `POST /agent/v1/tools/invoke` — mTLS-gated, the first `/agent/v1/*`
 * endpoint that actually *does* something beyond deciding (Phase 7b).
 * A thin wrapper: calls the EXISTING, unchanged `AuthorizationService`
 * (Phase 5/6) to get an `ALLOW | DENY | REQUIRE_APPROVAL` decision, then:
 *
 *   - `DENY` -> 403 with the decision's own `reason`; no tool call is ever
 *     attempted (`CredentialBrokerService.invoke` is never called).
 *   - `REQUIRE_APPROVAL` -> 202, `{ status: 'PENDING', reason, riskScore }`
 *     — a clearly-not-success, clearly-not-failure signal, same dead end
 *     Phase 6 left this decision at (Phase 8 gives it a real fulfillment
 *     path); no tool call is ever attempted here either.
 *   - `ALLOW` -> `CredentialBrokerService.invoke(...)`, whose
 *     `ToolInvocationResult` (itself possibly `{ success: false, ... }` if
 *     the *tool* failed — a request the gateway itself handled
 *     successfully, distinct from an authorization failure) is returned
 *     as the response body. `ToolNotFoundError`/`ToolActionNotFoundError`
 *     (the requested `toolId`/`actionId` don't resolve to a registered
 *     tool at all) map to 404; `ToolDisabledError` maps to 409.
 *
 * Never duplicates or forks `AuthorizationService`'s own pipeline.
 */
@Controller('agent/v1')
export class ToolInvokeController {
  constructor(
    private readonly authorizationService: AuthorizationService,
    private readonly credentialBroker: CredentialBrokerService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post('tools/invoke')
  @UseGuards(AgentMtlsGuard)
  async invoke(
    @CurrentAgent() agent: AgentContext,
    @Body() body: unknown,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const input = parseBodyOrThrow(ToolInvokeRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      agent.tenant.id,
    );

    const decision = await this.authorizationService.authorize(
      tenantClient,
      agent.tenant.id,
      agent.agent.id,
      {
        taskId: input.taskId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
      },
    );

    if (decision.decision === 'DENY') {
      // Unlike POST /agent/v1/authorize (which always answers 200/201 —
      // see AuthorizeController's own doc comment), this endpoint's DENY
      // maps to a real 403: the design spec asks for it explicitly, and
      // there is no equivalent "learn the shape of the model from the
      // status code" concern here (this endpoint doesn't expose a
      // separate authorize-only surface a caller could probe).
      throw new ForbiddenException({
        decision: 'DENY',
        reason: decision.reason,
      });
    }
    if (decision.decision === 'REQUIRE_APPROVAL') {
      // A clearly-not-success, clearly-not-failure signal (202) — no tool
      // call is attempted; Phase 8 gives this decision a real fulfillment
      // path later (same dead end Phase 6 already left it at).
      reply.status(202);
      return {
        status: 'PENDING',
        reason: decision.reason,
        riskScore: decision.riskScore,
      };
    }

    try {
      return await this.credentialBroker.invoke(tenantClient, {
        taskId: input.taskId,
        agentId: agent.agent.id,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        params: input.params,
      });
    } catch (error) {
      if (error instanceof ToolNotFoundError) {
        throw new NotFoundException(error.message);
      }
      if (error instanceof ToolActionNotFoundError) {
        throw new NotFoundException(error.message);
      }
      if (error instanceof ToolDisabledError) {
        throw new ConflictException(error.message);
      }
      throw error;
    }
  }
}
