export interface GrowthActivities {
  sendDueDigests(): Promise<{ sent: number; skipped: number; failed: number }>;
  sendTrialReminders(): Promise<{ sent: number; failed: number }>;
  executeDueDeletions(): Promise<{ done: number; failed: number }>;
}
