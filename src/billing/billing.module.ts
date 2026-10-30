import { Global, Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { BillableUsageService } from './billable-usage.service';
import {
  BillingController,
  StripeWebhookController,
} from './billing.controller';
import { BillingService } from './billing.service';
import { CompanyQuantityService } from './company-quantity.service';
import { EntitlementsService } from './entitlements.service';
import { ReadOnlyInterceptor } from './read-only.interceptor';
import { StripeWebhookService } from './stripe-webhook.service';
import { StripeGateway } from './stripe.gateway';

/** Plans and limits, for every module that enforces them. */
@Global()
@Module({
  providers: [EntitlementsService],
  exports: [EntitlementsService],
})
export class BillingModule {}

/** The console-facing billing API and the Stripe webhook. Imported only into AppModule. */
@Module({
  controllers: [BillingController, StripeWebhookController],
  providers: [
    BillingService,
    BillableUsageService,
    StripeGateway,
    StripeWebhookService,
    { provide: APP_INTERCEPTOR, useClass: ReadOnlyInterceptor },
  ],
})
export class BillingHttpModule {}

/** The daily Company quantity job. Imported only into the worker. */
@Module({
  imports: [BillingModule],
  providers: [BillableUsageService, StripeGateway, CompanyQuantityService],
})
export class BillingWorkerModule {}
