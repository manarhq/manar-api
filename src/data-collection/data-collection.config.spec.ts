import { describe, expect, it } from 'vitest';
import {
  dataCollectionConfigIssues as issues,
  DataCollectionConfigSchema,
} from './data-collection.config';

const parse = (o: Record<string, string>) =>
  DataCollectionConfigSchema.parse(o);
const secret = 's'.repeat(32);

describe('dataCollectionConfigIssues', () => {
  it('PostHog off needs nothing', () => {
    expect(issues(parse({}))).toEqual([]);
  });
  it('refuses a half-configured PostHog', () => {
    expect(
      issues(
        parse({ POSTHOG_API_KEY: 'k', DATA_COLLECTION_HASH_SECRET: secret }),
      ),
    ).toHaveLength(1);
    expect(
      issues(
        parse({
          POSTHOG_API_KEY: 'k',
          DATA_COLLECTION_HASH_SECRET: secret,
          POSTHOG_PERSONAL_API_KEY: 'p',
        }),
      ),
    ).not.toEqual([]);
    expect(
      issues(
        parse({
          POSTHOG_API_KEY: 'k',
          POSTHOG_PERSONAL_API_KEY: 'p',
          POSTHOG_PROJECT_ID: '1',
        }),
      ),
    ).toHaveLength(1); // no hash secret
  });
  it('accepts a complete setup', () => {
    expect(
      issues(
        parse({
          POSTHOG_API_KEY: 'k',
          DATA_COLLECTION_HASH_SECRET: secret,
          POSTHOG_PERSONAL_API_KEY: 'p',
          POSTHOG_PROJECT_ID: '12',
        }),
      ),
    ).toEqual([]);
  });
});
