import {
  Client,
  ScheduleAlreadyRunning,
  ScheduleOverlapPolicy,
  type Connection,
} from '@temporalio/client';

export const GROWTH_SCHEDULE_ID = 'manar-growth-hourly';

/**
 * Creates the hourly Growth schedule if it does not exist (safe on every worker start: an
 * existing one is left alone). Each tick starts `GrowthTickWorkflow`; a tick still running when
 * the next is due is skipped.
 */
export async function ensureGrowthSchedule(
  connection: Connection,
  namespace: string,
  taskQueue: string,
): Promise<'created' | 'exists'> {
  const client = new Client({ connection, namespace });
  try {
    await client.schedule.create({
      scheduleId: GROWTH_SCHEDULE_ID,
      spec: { cronExpressions: ['5 * * * *'], timezone: 'UTC' },
      policies: {
        overlap: ScheduleOverlapPolicy.SKIP,
        catchupWindow: '1 hour',
      },
      action: {
        type: 'startWorkflow',
        workflowType: 'GrowthTickWorkflow',
        taskQueue,
        workflowId: 'manar-growth-tick',
        args: [],
      },
    });
    return 'created';
  } catch (error) {
    if (error instanceof ScheduleAlreadyRunning) return 'exists';
    throw error;
  }
}
