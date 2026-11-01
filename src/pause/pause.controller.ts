import { Body, Controller, Get, Put, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiExcludeController,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { PauseService } from './pause.service';

const SetPauseSchema = z.object({
  paused: z.boolean(),
  via: z.enum(['console', 'phone']).optional(),
});

/** `/workspace/pause`: the Home button and the phone use these two routes. */
// Not in the generated console client yet (manar-web calls it through the BFF), so the committed
// schema does not drift. Include it when a live regeneration is next run.
@ApiExcludeController()
@ApiTags('workspace')
@ApiBearerAuth('jwt')
@Controller('workspace/pause')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('APPROVER', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class PauseController {
  constructor(private readonly pause: PauseService) {}

  @Get()
  @ApiOperation({ summary: 'Is every protected tool paused?' })
  get(@CurrentAuth() auth: AuthContext) {
    return this.pause.get(auth.tenant.id);
  }

  @Put()
  @ApiOperation({
    summary: 'Pause all AI, or resume',
    description:
      'While paused every protected tool on every device is denied with reason `paused`, and nothing can be approved. Pending approvals are expired. Resuming needs a role at least as high as the one that paused.',
  })
  set(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(SetPauseSchema, body);
    return this.pause.set(
      auth.tenant.id,
      input.paused,
      auth.user.keycloakSubject,
      auth.roles,
      input.via,
    );
  }
}
