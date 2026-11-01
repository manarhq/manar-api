export interface GrowthActivities {
  sendDueDigests(): Promise<{ sent: number; skipped: number; failed: number }>;
  executeDueDeletions(): Promise<{ done: number; failed: number }>;
}
