import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  NotFoundException,
  OnModuleDestroy,
  OnModuleInit,
  Post,
  ServiceUnavailableException,
  HttpException,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiExcludeController,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  TelegramBotHandler,
  type TelegramUpdate,
} from './telegram-bot.handler';
import { TelegramService } from './telegram.service';

/**
 * Telegram's webhook. Public (Telegram calls it), so it answers only when the secret header
 * matches: wrong or missing secret is 401, bot not configured is 404. Rate limited per address.
 */
@ApiExcludeController()
@Controller('telegram')
// A generous global cap per address (Telegram's servers are shared by every bot); the real limits
// are per chat and user in TelegramBotHandler, after the secret check.
@Throttle({ human: { limit: 3000, ttl: 60_000 } })
export class TelegramWebhookController
  implements OnModuleInit, OnModuleDestroy
{
  constructor(
    private readonly telegram: TelegramService,
    private readonly bot: TelegramBotHandler,
  ) {}

  onModuleInit() {
    void this.telegram.registerWebhook();
    this.telegram.startSweeper();
  }

  onModuleDestroy() {
    this.telegram.stopSweeper();
  }

  @Post('webhook')
  @HttpCode(200)
  async webhook(
    @Headers('x-telegram-bot-api-secret-token') secret: string | undefined,
    @Body() update: TelegramUpdate,
  ) {
    if (!this.telegram.enabled) throw new NotFoundException();
    if (!this.telegram.verifyWebhookSecret(secret))
      throw new UnauthorizedException();
    // Telegram retries on any non-2xx, so a handled-and-failed update is still a 200.
    await this.bot.handle(update ?? {});
    return {};
  }
}

@ApiTags('push')
@ApiBearerAuth('jwt')
@Controller('telegram/link')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('APPROVER', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class TelegramLinkController {
  constructor(
    private readonly telegram: TelegramService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Is the Telegram bot on, and is this person linked?',
  })
  async status(@CurrentAuth() auth: AuthContext) {
    if (!this.telegram.enabled) return { enabled: false, linked: 0 };
    const links = await this.telegram.linksFor(
      auth.tenant.id,
      auth.user.keycloakSubject,
    );
    return {
      enabled: true,
      linked: links.length,
      botUsername: this.telegram.botUsername,
    };
  }

  @Post()
  @ApiOperation({
    summary: 'Make a one-time code to link a Telegram chat (valid 10 minutes)',
  })
  async code(@CurrentAuth() auth: AuthContext) {
    if (!this.telegram.enabled)
      throw new ServiceUnavailableException('telegram is not configured');
    try {
      return await this.telegram.createLinkCode(
        auth.tenant.id,
        auth.user.keycloakSubject,
      );
    } catch {
      throw new HttpException('too many codes, try again later', 429);
    }
  }

  @Delete()
  @HttpCode(204)
  @ApiOperation({ summary: 'Unlink every Telegram chat of this person' })
  async unlink(@CurrentAuth() auth: AuthContext) {
    const n = await this.telegram.unlinkPerson(
      auth.tenant.id,
      auth.user.keycloakSubject,
    );
    if (n > 0) {
      const client = await this.tenants.getClient(auth.tenant.id);
      await this.audit.recordSafely(client, auth.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.TELEGRAM_LINK_REMOVED,
        actor: { type: 'human', id: auth.user.keycloakSubject },
        data: { chats: n },
      });
    }
  }
}
