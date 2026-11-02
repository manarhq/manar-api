import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * Product improvement data. Forwarding to PostHog EU is off until `POSTHOG_API_KEY` (the project
 * ingestion key) is set; events are then dropped. `DATA_COLLECTION_HASH_SECRET` keys the HMAC that
 * turns a person into the PostHog `distinct_id`, so it is required whenever forwarding is on.
 * Person deletion (opt-out, account deletion) needs a personal API key and the project id; without
 * them the request is logged and PostHog's own retention applies.
 */
export const DataCollectionConfigSchema = z.object({
  POSTHOG_API_KEY: optional,
  POSTHOG_PERSONAL_API_KEY: optional,
  POSTHOG_PROJECT_ID: optional.pipe(
    z
      .string()
      .regex(/^\d{1,12}$/)
      .optional(),
  ),
  DATA_COLLECTION_HASH_SECRET: optional.pipe(z.string().min(32).optional()),
});

export type DataCollectionConfig = z.infer<typeof DataCollectionConfigSchema>;

export function dataCollectionConfigIssues(c: DataCollectionConfig): string[] {
  const issues: string[] = [];
  if (c.POSTHOG_API_KEY && !c.DATA_COLLECTION_HASH_SECRET)
    issues.push(
      'DATA_COLLECTION_HASH_SECRET (32+ chars) is required when POSTHOG_API_KEY is set',
    );
  // The privacy policy promises person deletion on opt-out: refuse to start without the means.
  if (
    c.POSTHOG_API_KEY &&
    !(c.POSTHOG_PERSONAL_API_KEY && c.POSTHOG_PROJECT_ID)
  )
    issues.push(
      'POSTHOG_PERSONAL_API_KEY and POSTHOG_PROJECT_ID are required when POSTHOG_API_KEY is set (person deletion)',
    );
  if (!c.POSTHOG_PERSONAL_API_KEY !== !c.POSTHOG_PROJECT_ID)
    issues.push(
      'POSTHOG_PERSONAL_API_KEY and POSTHOG_PROJECT_ID must be set together',
    );
  return issues;
}
