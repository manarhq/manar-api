import {
  Body,
  ConflictException,
  Controller,
  Get,
  Headers,
  HttpCode,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiExcludeController,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { BillingService, CHECKOUT_PLANS } from './billing.service';
import { ContactEmailService } from '../contact/contact-email.service';
import { StripeWebhookService } from './stripe-webhook.service';
import { WalletService } from './wallet.service';

const CheckoutSchema = z.object({
  plan: z.enum(CHECKOUT_PLANS),
  /** Company yearly: seats to commit for the year (at least 3). */
  seats: z.number().int().min(3).max(10_000).optional(),
});
const DailyQuerySchema = z.object({
  days: z.coerce.number().int().min(1).max(90).default(30),
});
const CreditsSchema = z.object({ packs: z.number().int().min(1).max(20) });
const WalletSchema = z
  .object({
    /** Monthly cap in USD above the allowance; null = no cap. */
    capUsd: z.number().int().min(0).max(100_000).nullable().optional(),
    autoTopUp: z.boolean().optional(),
  })
  .strict();

@ApiTags('billing')
@ApiBearerAuth('jwt')
@Controller('billing')
export class BillingController {
  constructor(
    private readonly billing: BillingService,
    private readonly wallet: WalletService,
    private readonly contact: ContactEmailService,
  ) {}

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({
    summary: "Plan, limits, features and usage of the caller's workspace",
  })
  status(@CurrentAuth() auth: AuthContext) {
    return this.billing.status(auth.tenant.id);
  }

  @Post('checkout')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER')
  @ApiOperation({
    summary:
      'Stripe Checkout session URL for Pro (monthly or yearly), Company (monthly, yearly) or the Company trial',
  })
  async checkout(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const { plan, seats } = parseBodyOrThrow(CheckoutSchema, body);
    const email = await this.verifiedEmail(auth);
    return this.billing.checkout(auth.tenant.id, email, plan, seats);
  }

  /** The token's email can be the realm's `.invalid` placeholder: Stripe gets the verified one. */
  private async verifiedEmail(auth: AuthContext): Promise<string> {
    const email = await this.contact.verified(
      auth.issuer,
      auth.user.keycloakSubject,
    );
    if (!email)
      throw new ConflictException({
        statusCode: 409,
        code: 'contact_email_required',
        message: 'Confirm a contact email before checkout.',
      });
    return email;
  }

  @Get('usage')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({
    summary:
      'Usage and bill so far this month: allowance, credits, active devices or seats, forecast',
  })
  usage(@CurrentAuth() auth: AuthContext) {
    return this.wallet.usage(auth.tenant.id);
  }

  @Get('usage/daily')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({
    summary:
      "The workspace's AI actions per day (allowance and credits), plus the month figures",
    description:
      'For the AI usage page. `days` 1 to 90 (default 30), UTC days, oldest first, empty days included. Each day splits into `fromAllowance` and `fromCredits` (1 credit = 1 AI action); the sum over a month equals `allowance.ai.used` on `GET /billing/usage`.',
  })
  dailyUsage(@CurrentAuth() auth: AuthContext, @Query() query: unknown) {
    const { days } = parseBodyOrThrow(DailyQuerySchema, query);
    return this.wallet.dailyAiUsage(auth.tenant.id, days);
  }

  @Put('wallet')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER')
  @ApiOperation({ summary: 'Set the monthly spend cap and auto top-up' })
  updateWallet(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    return this.wallet.updateSettings(
      auth.tenant.id,
      parseBodyOrThrow(WalletSchema, body),
    );
  }

  @Post('credits')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER')
  @ApiOperation({
    summary:
      'Stripe Checkout session URL for credit packs ($5 = 1,000 credits)',
  })
  async credits(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const { packs } = parseBodyOrThrow(CreditsSchema, body);
    return this.billing.buyCredits(
      auth.tenant.id,
      await this.verifiedEmail(auth),
      packs,
    );
  }

  @Post('trial/cancel')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER')
  @ApiOperation({
    summary: 'Cancel the Company trial now (one click); nothing is charged',
  })
  cancelTrial(@CurrentAuth() auth: AuthContext) {
    return this.billing.cancelTrial(auth.tenant.id);
  }

  @Post('portal')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER')
  @ApiOperation({
    summary:
      'Stripe Customer Portal session URL (plan, payment method, invoices)',
  })
  portal(@CurrentAuth() auth: AuthContext) {
    return this.billing.portal(auth.tenant.id);
  }
}

/** Public: authenticated by Stripe's signature over the raw body, rate-limited by the global guard. */
@ApiExcludeController()
@Controller('billing/stripe')
export class StripeWebhookController {
  constructor(private readonly webhook: StripeWebhookService) {}

  @Post('webhook')
  @HttpCode(200)
  handle(
    @Req() req: FastifyRequest & { rawBody?: Buffer },
    @Headers('stripe-signature') signature: string | undefined,
  ) {
    return this.webhook.handle(req.rawBody, signature);
  }
}
