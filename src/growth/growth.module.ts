import { Module } from '@nestjs/common';
import { BillingHttpModule } from '../billing/billing.module';
import { StripeGateway } from '../billing/stripe.gateway';
import { KeycloakModule } from '../keycloak/keycloak.module';
import { ReportCardService } from '../workspace/report-card.service';
import { WorkspaceProvisioningService } from '../workspaces/workspace-provisioning.service';
import { DataCollectionModule } from '../data-collection/data-collection.module';
import { RedisThrottlerStorageModule } from '../rate-limit/redis-throttler-storage.module';
import { AccountService } from './account.service';
import { ContactFlowService } from './contact-flow.service';
import { DigestService } from './digest.service';
import { GrowthAuditService } from './growth-audit.service';
import {
  GrowthIdentityController,
  GrowthPublicController,
  GrowthWorkspaceController,
} from './growth.controller';
import { MailerService } from './mailer.service';
import { MembersService } from './members.service';
import { PersonalTrialService } from './personal-trial.service';
import { BillingTickService } from '../billing/billing-tick.service';
import { UsageAlertsService } from '../billing/usage-alerts.service';
import { ProfileService } from './profile.service';

const SHARED = [
  GrowthAuditService,
  MailerService,
  ReportCardService,
  DigestService,
  PersonalTrialService,
  // Account deletion removes the workspace; the queue loop is not started here.
  WorkspaceProvisioningService,
  AccountService,
];

/** Growth track, HTTP app: personal trial, badge, invites and auto-join, account deletion. */
@Module({
  imports: [
    BillingHttpModule,
    DataCollectionModule,
    // WorkspaceProvisioningService's creation gate.
    RedisThrottlerStorageModule,
  ],
  controllers: [
    GrowthPublicController,
    GrowthWorkspaceController,
    GrowthIdentityController,
  ],
  providers: [...SHARED, ContactFlowService, ProfileService, MembersService],
  exports: [PersonalTrialService],
})
export class GrowthModule {}

/** Growth track, worker: the hourly digest, trial reminders, billing tick and account deletion. */
@Module({
  imports: [KeycloakModule, DataCollectionModule, RedisThrottlerStorageModule],
  providers: [...SHARED, StripeGateway, BillingTickService, UsageAlertsService],
  exports: [
    DigestService,
    AccountService,
    PersonalTrialService,
    BillingTickService,
    UsageAlertsService,
    DataCollectionModule,
  ],
})
export class GrowthWorkerModule {}
