import { Injectable } from '@nestjs/common';
import { AccountService } from '../../growth/account.service';
import { DigestService } from '../../growth/digest.service';
import type { GrowthActivities } from './growth-activities.interface';

@Injectable()
export class GrowthActivitiesFactory {
  constructor(
    private readonly digest: DigestService,
    private readonly account: AccountService,
  ) {}

  build(): GrowthActivities {
    return {
      sendDueDigests: () => this.digest.sendDue(),
      executeDueDeletions: () => this.account.executeDue(),
    };
  }
}
