import { Body, Controller, HttpCode, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { PhoneActionsService } from './phone-actions.service';

const PushDecideSchema = z.object({
  token: z.string().min(20).max(1024),
  decision: z.enum(['approve_once', 'deny']),
});

@ApiTags('push')
@ApiBearerAuth('jwt')
@Controller('phone')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('APPROVER', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class PhoneController {
  constructor(private readonly actions: PhoneActionsService) {}

  @Post('push-decide')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Approve once or deny from a notification button',
    description:
      'Needs the signed-in session and the single-use token from the push. Never for high-risk approvals.',
  })
  async pushDecide(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(PushDecideSchema, body);
    const r = await this.actions.decideFromPush(
      auth,
      input.token,
      input.decision,
    );
    return { id: r.id, status: r.status, decision: r.decision };
  }
}
