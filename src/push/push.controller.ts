import {
  Body,
  Controller,
  Delete,
  Get,
  Post,
  HttpCode,
  ServiceUnavailableException,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { PushService } from './push.service';
import { isAllowedPushEndpoint } from './push-endpoint';

const SubscribeSchema = z.object({
  endpoint: z
    .url()
    .max(2048)
    .refine(isAllowedPushEndpoint, 'not a browser push service'),
  keys: z.object({
    p256dh: z.string().min(1).max(256),
    auth: z.string().min(1).max(64),
  }),
});
const UnsubscribeSchema = z.object({ endpoint: z.url().max(2048) });

@ApiTags('push')
@ApiBearerAuth('jwt')
@Controller('push')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('APPROVER', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class PushController {
  constructor(private readonly push: PushService) {}

  @Get('vapid-key')
  @ApiOperation({ summary: 'The public VAPID key for pushManager.subscribe' })
  vapidKey() {
    return { enabled: this.push.enabled, publicKey: this.push.publicKey };
  }

  @Post('subscriptions')
  @HttpCode(204)
  @ApiOperation({ summary: 'Register this browser for approval notifications' })
  async subscribe(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(SubscribeSchema, body);
    if (!this.push.enabled)
      throw new ServiceUnavailableException('push is not configured');
    await this.push.subscribe(auth.user.keycloakSubject, auth.tenant.id, {
      endpoint: input.endpoint,
      p256dh: input.keys.p256dh,
      auth: input.keys.auth,
    });
  }

  @Delete('subscriptions')
  @HttpCode(204)
  @ApiOperation({ summary: 'Stop notifications to this browser' })
  async unsubscribe(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(UnsubscribeSchema, body);
    await this.push.unsubscribe(auth.user.keycloakSubject, input.endpoint);
  }
}
