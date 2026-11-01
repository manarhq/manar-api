import { Module } from '@nestjs/common';
import { BillingHttpModule } from '../billing/billing.module';
import { StripeGateway } from '../billing/stripe.gateway';
import { KeycloakModule } from '../keycloak/keycloak.module';
import { ReportCardService } from '../workspace/report-card.service';
import { WorkspaceProvisioningService } from '../workspaces/workspace-provisioning.service';
import { AccountService } from './account.service';
import { ContactFlowService } from './contact-flow.service';
import { DigestService } from './digest.service';
import { GrowthAuditService } from './growth-audit.service';
import {
  GrowthIdentityController,
  GrowthPublicController,
  GrowthWorkspaceController,
} from './growth.controller';
import { LaunchOfferService } from './launch-offer.service';
import { MailerService } from './mailer.service';
import { MembersService } from './members.service';
import { TrialReminderService } from './trial-reminder.service';
import { ProfileService } from './profile.service';

const SHARED = [
  GrowthAuditService,
  MailerService,
  ReportCardService,
  DigestService,
  TrialReminderService,
  // Account deletion removes the workspace; the queue loop is not started here.
  WorkspaceProvisioningService,
  AccountService,
];

/** Growth track, HTTP app: launch offer, badge, invites and auto-join, account deletion. */
@Module({
  imports: [BillingHttpModule],
  controllers: [
    GrowthPublicController,
    GrowthWorkspaceController,
    GrowthIdentityController,
  ],
  providers: [
    ...SHARED,
    ContactFlowService,
    LaunchOfferService,
    ProfileService,
    MembersService,
  ],
  exports: [LaunchOfferService],
})
export class GrowthModule {}

/** Growth track, worker: the hourly digest and account-deletion activities. */
@Module({
  imports: [KeycloakModule],
  providers: [...SHARED, StripeGateway],
  exports: [DigestService, AccountService],
})
export class GrowthWorkerModule {}
