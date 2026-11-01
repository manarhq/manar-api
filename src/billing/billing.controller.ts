import {
  Body,
  ConflictException,
  Controller,
  Get,
  Headers,
  HttpCode,
  Post,
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
import { BillingService } from './billing.service';
import { ContactEmailService } from '../contact/contact-email.service';
import { KeepProService } from './keep-pro.service';
import { StripeWebhookService } from './stripe-webhook.service';

const CheckoutSchema = z.object({
  plan: z.enum(['pro_monthly', 'pro_yearly', 'company']),
});

@ApiTags('billing')
@ApiBearerAuth('jwt')
@Controller('billing')
export class BillingController {
  constructor(
    private readonly billing: BillingService,
    private readonly keepPro: KeepProService,
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
      'Stripe Checkout session URL for Pro (monthly or yearly) or Company',
  })
  async checkout(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const { plan } = parseBodyOrThrow(CheckoutSchema, body);
    // The token's email can be the realm's `.invalid` placeholder: Stripe gets the verified one.
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
    return this.billing.checkout(auth.tenant.id, email, plan);
  }

  @Post('keep-pro')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('TENANT_OWNER')
  @ApiOperation({
    summary: 'Keep Pro after the launch-offer free months',
    description:
      'Stripe Checkout (setup mode) URL collecting a card, billing address and tax id. On completion automatic tax is turned on for the subscription.',
  })
  keepProSession(@CurrentAuth() auth: AuthContext) {
    return this.keepPro.createSession(auth.tenant.id);
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
