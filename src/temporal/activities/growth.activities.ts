import { Injectable } from '@nestjs/common';
import { AccountService } from '../../growth/account.service';
import { DigestService } from '../../growth/digest.service';
import { TrialReminderService } from '../../growth/trial-reminder.service';
import type { GrowthActivities } from './growth-activities.interface';

@Injectable()
export class GrowthActivitiesFactory {
  constructor(
    private readonly digest: DigestService,
    private readonly account: AccountService,
    private readonly reminders: TrialReminderService,
  ) {}

  build(): GrowthActivities {
    return {
      sendDueDigests: () => this.digest.sendDue(),
      sendTrialReminders: () => this.reminders.sendDue(),
      executeDueDeletions: () => this.account.executeDue(),
    };
  }
}
