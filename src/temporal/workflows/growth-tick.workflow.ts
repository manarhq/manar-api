import { proxyActivities } from '@temporalio/workflow';
import type { GrowthActivities } from '../activities/growth-activities.interface';

const activities = proxyActivities<GrowthActivities>({
  startToCloseTimeout: '10 minutes',
  retry: {
    initialInterval: '5 seconds',
    backoffCoefficient: 2,
    maximumAttempts: 3,
  },
});

/**
 * One tick of the hourly Growth schedule (`ensureGrowthSchedule`): the weekly "Your AI week"
 * emails that are due (Monday morning in each person's time zone), then the account deletions
 * whose 7-day grace period ended. Both are idempotent, so an overlapping or repeated tick is
 * harmless.
 */
export async function GrowthTickWorkflow(): Promise<void> {
  await activities.sendDueDigests();
  await activities.executeDueDeletions();
}
