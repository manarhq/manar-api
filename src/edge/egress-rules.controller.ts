import {
  Body,
  ConflictException,
  Controller,
  Delete,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  Post,
  UnprocessableEntityException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { z } from 'zod';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { EdgePeerService } from './edge-peer.service';
import { normalizeEgressHost } from './edge-net';

/** Keeps one agent's allow-list (and the gateway's per-peer list) bounded. */
const MAX_RULES_PER_AGENT = 200;

const AddRuleSchema = z.object({
  host: z
    .string()
    .max(253)
    .transform((h, ctx) => {
      const host = normalizeEgressHost(h);
      if (!host) {
        ctx.addIssue({
          code: 'custom',
          message:
            'host must be a DNS name or *. + a DNS name (no IPs, ports or paths, max 253)',
        });
        return z.NEVER;
      }
      return host;
    }),
  reason: z.string().min(1).max(500).optional(),
});

/**
 * Per-agent egress allow-list (docs/edge.md section 4). Human tenant admins only (JWT + role, the
 * same gate as the rest of `/agents`); this controller exists only on the HTTP app, so an agent
 * certificate cannot reach it, and no AI tool writes it. Each change commits with its audit event
 * (no event, no change), then updates the agent's edge peer and bumps the version.
 */
@ApiTags('agents')
@ApiBearerAuth('jwt')
@Controller('agents/:id/egress-rules')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
export class EgressRulesController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    private readonly peers: EdgePeerService,
  ) {}

  private async agentDb(
    auth: AuthContext,
    agentId: string,
  ): Promise<TenantPrismaClient> {
    const db = await this.tenants.getClient(auth.tenant.id);
    const agent = await db.agent.findUnique({
      where: { id: agentId },
      select: { id: true },
    });
    if (!agent) throw new NotFoundException(`Agent "${agentId}" was not found`);
    return db;
  }

  @Get()
  @ApiOperation({ summary: "List an agent's egress allow-list" })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async list(@CurrentAuth() auth: AuthContext, @Param('id') agentId: string) {
    const db = await this.agentDb(auth, agentId);
    const items = await db.agentEgressRule.findMany({
      where: { agentId },
      orderBy: { host: 'asc' },
    });
    return { items };
  }

  @Post()
  @ApiOperation({
    summary: 'Allow the agent to reach a host through the edge proxy',
    description:
      'host: a DNS name or `*.` + a DNS name (one label or more), lowercased; no IPs, ports or paths. 409 if already allowed.',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async add(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(AddRuleSchema, body);
    const db = await this.agentDb(auth, agentId);
    const { rule, publish } = await db.$transaction(async (tx) => {
      const existing = await tx.agentEgressRule.findUnique({
        where: { agentId_host: { agentId, host: input.host } },
      });
      if (existing) throw new ConflictException('Host is already allowed');
      if (
        (await tx.agentEgressRule.count({ where: { agentId } })) >=
        MAX_RULES_PER_AGENT
      )
        throw new UnprocessableEntityException(
          `At most ${MAX_RULES_PER_AGENT} egress rules per agent`,
        );
      const rule = await tx.agentEgressRule.create({
        data: {
          agentId,
          host: input.host,
          reason: input.reason ?? null,
          createdBy: auth.user.id,
        },
      });
      const publish = await this.audit.recordInTransaction(tx, auth.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.AGENT_EGRESS_RULE_ADDED,
        actor: { type: 'human', id: auth.user.id },
        data: {
          ruleId: rule.id,
          agentId,
          host: rule.host,
          reason: rule.reason,
        },
      });
      return { rule, publish };
    });
    publish();
    await this.peers.agentChanged(auth.tenant.id, agentId);
    return rule;
  }

  @Delete(':ruleId')
  @HttpCode(204)
  @ApiOperation({ summary: 'Remove a host from the agent egress allow-list' })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiParam({ name: 'ruleId', description: 'Rule ID', format: 'uuid' })
  @ApiResponse({ status: 204 })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async remove(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Param('ruleId') ruleId: string,
  ): Promise<void> {
    const db = await this.agentDb(auth, agentId);
    const publish = await db.$transaction(async (tx) => {
      const rule = await tx.agentEgressRule.findFirst({
        where: { id: ruleId, agentId },
      });
      if (!rule) throw new NotFoundException('Egress rule not found');
      await tx.agentEgressRule.delete({ where: { id: rule.id } });
      return this.audit.recordInTransaction(tx, auth.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.AGENT_EGRESS_RULE_REMOVED,
        actor: { type: 'human', id: auth.user.id },
        data: { ruleId: rule.id, agentId, host: rule.host },
      });
    });
    publish();
    await this.peers.agentChanged(auth.tenant.id, agentId);
  }
}
