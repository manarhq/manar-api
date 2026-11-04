import { Injectable } from '@nestjs/common';
import { AccountService } from '../../growth/account.service';
import { DataCollectionService } from '../../data-collection/data-collection.service';
import { DigestService } from '../../growth/digest.service';
import { BillingTickService } from '../../billing/billing-tick.service';
import { UsageAlertsService } from '../../billing/usage-alerts.service';
import { PersonalTrialService } from '../../growth/personal-trial.service';
import type { GrowthActivities } from './growth-activities.interface';

@Injectable()
export class GrowthActivitiesFactory {
  constructor(
    private readonly digest: DigestService,
    private readonly account: AccountService,
    private readonly trial: PersonalTrialService,
    private readonly billingTick: BillingTickService,
    private readonly alerts: UsageAlertsService,
    private readonly data: DataCollectionService,
  ) {}

  build(): GrowthActivities {
    return {
      sendDueDigests: () => this.digest.sendDue(),
      sendTrialReminders: () => this.trial.sendDue(),
      runBillingTick: () => this.billingTick.run(),
      sendUsageAlerts: () => this.alerts.sendDue(),
      executeDueDeletions: () => this.account.executeDue(),
      purgeOldSamples: () => this.data.purgeOld(),
    };
  }
}
