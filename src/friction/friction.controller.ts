import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import {
  OPERATOR_ROLES,
  isApproverRole,
} from '../approvals/approver-directory';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { FrictionService } from './friction.service';

export function parseDays(raw: string | undefined, fallback = 14): number {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) ? Math.min(90, Math.max(1, n)) : fallback;
}

/** "How much Manar asked you" (decision 38). Counts and times only; no prompt content. */
@ApiTags('friction')
@ApiBearerAuth('jwt')
@Controller('friction')
@UseGuards(JwtAuthGuard, RolesGuard)
export class FrictionController {
  constructor(
    private readonly friction: FrictionService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  @Get()
  @RequireRole(...OPERATOR_ROLES)
  @ApiOperation({
    summary: 'Prompts, answers, time blocked and the 5-a-day budget',
    description:
      'Per day, and per person for approvers. Anyone else sees only their own devices. Prompts shown, approvals, denies, denies later approved within 24 hours, time from prompt to answer, minutes blocked.',
  })
  @ApiQuery({
    name: 'days',
    required: false,
    description: '1 to 90, default 14',
  })
  async get(@CurrentAuth() auth: AuthContext, @Query('days') days?: string) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.friction.report(
      client,
      { subject: auth.user.keycloakSubject, admin: isApproverRole(auth.roles) },
      parseDays(days),
    );
  }
}
