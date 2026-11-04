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
 * emails that are due (Monday morning in each person's time zone), the personal trial reminders
 * (days 10, 13 and 14), the billing tick (active days, meter reports to Stripe) and the usage
 * alerts, then the account deletions whose 7-day grace period ended, then the product-improvement
 * samples older than 12 months. All are idempotent, so an overlapping or repeated tick is harmless.
 */
export async function GrowthTickWorkflow(): Promise<void> {
  await activities.sendDueDigests();
  await activities.sendTrialReminders();
  await activities.runBillingTick();
  await activities.sendUsageAlerts();
  await activities.executeDueDeletions();
  await activities.purgeOldSamples();
}
