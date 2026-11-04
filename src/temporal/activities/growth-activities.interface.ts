export interface GrowthActivities {
  sendDueDigests(): Promise<{ sent: number; skipped: number; failed: number }>;
  sendTrialReminders(): Promise<{ sent: number; failed: number }>;
  runBillingTick(): Promise<{
    tenants: number;
    queued: number;
    sent: number;
    failed: number;
  }>;
  sendUsageAlerts(): Promise<{ sent: number; failed: number }>;
  executeDueDeletions(): Promise<{ done: number; failed: number }>;
  purgeOldSamples(): Promise<{ deleted: number }>;
}
