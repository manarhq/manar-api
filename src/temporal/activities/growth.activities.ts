import { Injectable, Logger } from '@nestjs/common';
import { FrictionService } from '../../friction/friction.service';
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
    private readonly friction: FrictionService,
  ) {}

  private readonly logger = new Logger(GrowthActivitiesFactory.name);

  build(): GrowthActivities {
    return {
      sendDueDigests: () => this.digest.sendDue(),
      sendTrialReminders: () => this.trial.sendDue(),
      runBillingTick: () => this.billingTick.run(),
      sendUsageAlerts: async () => {
        const sent = await this.alerts.sendDue();
        // Friction alert (decision 38): awaited so the activity owns the work, after the alerts so
        // a slow rollup never delays them. Once per 6 hours across replicas; a failure only logs.
        try {
          await this.friction.scan();
        } catch (e: unknown) {
          this.logger.warn(`friction scan failed: ${String(e)}`);
        }
        return sent;
      },
      executeDueDeletions: () => this.account.executeDue(),
      purgeOldSamples: () => this.data.purgeOld(),
    };
  }
}
