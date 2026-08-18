import {
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TaskNotFoundError } from '../tasks/tasks.errors';
import { DelegationService } from './delegation.service';
import {
  DelegationExceedsParentAuthorityError,
  DelegationNotAssignedAgentError,
  DelegationTaskNotLiveError,
} from './delegation.errors';
import { DelegateTaskRequestSchema } from './delegation.validation';

function isUniqueConstraintViolation(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'P2002'
  );
}

/**
 * `POST /agent/v1/tasks/:id/delegate` — mTLS-gated, the caller must be the
 * target task's `assignedAgentId` (enforced inside `DelegationService`,
 * not by a role check — there is no human role concept on this surface).
 */
@Controller('agent/v1')
export class DelegationController {
  constructor(
    private readonly delegationService: DelegationService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post('tasks/:id/delegate')
  @UseGuards(AgentMtlsGuard)
  async delegate(
    @CurrentAgent() agent: AgentContext,
    @Param('id') taskId: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(DelegateTaskRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      agent.tenant.id,
    );

    try {
      const result = await this.delegationService.delegate(
        tenantClient,
        agent.tenant.id,
        agent.tenant.slug,
        taskId,
        agent.agent.id,
        input,
      );

      return {
        childTask: {
          id: result.childTask.id,
          status: result.childTask.status,
          assignedAgentId: result.childTask.assignedAgentId,
          parentTaskId: result.childTask.parentTaskId,
          expiresAt: result.childTask.expiresAt,
        },
        childAgent: result.childAgent,
        enrollmentToken: result.enrollmentToken,
      };
    } catch (error) {
      if (error instanceof TaskNotFoundError) {
        throw new NotFoundException(error.message);
      }
      if (error instanceof DelegationNotAssignedAgentError) {
        throw new ForbiddenException(error.message);
      }
      if (error instanceof DelegationTaskNotLiveError) {
        throw new ConflictException(error.message);
      }
      if (error instanceof DelegationExceedsParentAuthorityError) {
        throw new ForbiddenException(error.message);
      }
      if (isUniqueConstraintViolation(error)) {
        throw new ConflictException(
          `Agent slug "${input.childAgentSlug}" is already in use`,
        );
      }
      throw error;
    }
  }
}
