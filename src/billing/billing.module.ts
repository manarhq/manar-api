import { Global, Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { BillableUsageService } from './billable-usage.service';
import { BillingTickService } from './billing-tick.service';
import {
  BillingController,
  StripeWebhookController,
} from './billing.controller';
import { BillingService } from './billing.service';
import { EntitlementsService } from './entitlements.service';
import { ReadOnlyInterceptor } from './read-only.interceptor';
import { StripeWebhookService } from './stripe-webhook.service';
import { StripeGateway } from './stripe.gateway';
import { UsageMeterService } from './usage-meter.service';
import { WalletService } from './wallet.service';

/** Plans, limits and the usage meter, for every module that enforces or meters them. */
@Global()
@Module({
  providers: [EntitlementsService, UsageMeterService],
  exports: [EntitlementsService, UsageMeterService],
})
export class BillingModule {}

/** The console-facing billing API and the Stripe webhook. Imported only into AppModule. */
@Module({
  controllers: [BillingController, StripeWebhookController],
  providers: [
    BillingService,
    BillableUsageService,
    BillingTickService,
    StripeGateway,
    StripeWebhookService,
    WalletService,
    { provide: APP_INTERCEPTOR, useClass: ReadOnlyInterceptor },
  ],
  exports: [BillingService, StripeGateway],
})
export class BillingHttpModule {}

/** Worker: plans and the meter. The hourly billing tick runs in the Growth worker module. */
@Module({ imports: [BillingModule] })
export class BillingWorkerModule {}
