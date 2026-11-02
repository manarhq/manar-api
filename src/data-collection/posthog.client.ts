import { createHmac } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';

const INGEST = 'https://eu.i.posthog.com/batch/';
const API = 'https://eu.posthog.com/api/projects';

export interface PostHogEvent {
  event: string;
  /** From `distinctId()`: never an email or a name. */
  distinctId: string;
  at: Date;
  properties: Record<string, string | number | boolean>;
}

/** PostHog EU over plain fetch, server side only. Every method is a no-op without its key and never throws. */
@Injectable()
export class PostHogClient {
  private readonly logger = new Logger(PostHogClient.name);

  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  get enabled(): boolean {
    return !!this.config.get('POSTHOG_API_KEY', { infer: true });
  }

  /** HMAC-SHA256 of the person under a server secret (hex). */
  distinctId(issuer: string, subject: string): string {
    const secret = this.config.get('DATA_COLLECTION_HASH_SECRET', {
      infer: true,
    });
    return createHmac('sha256', secret ?? '')
      .update(`${issuer}\n${subject}`)
      .digest('hex');
  }

  async capture(events: PostHogEvent[]): Promise<void> {
    const key = this.config.get('POSTHOG_API_KEY', { infer: true });
    if (!key || events.length === 0) return;
    try {
      const res = await fetch(INGEST, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          api_key: key,
          batch: events.map((e) => ({
            event: e.event,
            distinct_id: e.distinctId,
            timestamp: e.at.toISOString(),
            properties: {
              ...e.properties,
              $lib: 'manar-api',
              $geoip_disable: true,
            },
          })),
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) this.logger.warn(`posthog capture failed: ${res.status}`);
    } catch (e) {
      this.logger.warn(`posthog capture failed: ${(e as Error).message}`);
    }
  }

  /** Ask PostHog to delete the person and their events. Needs a personal API key and the project id. */
  async deletePerson(distinctId: string): Promise<void> {
    if (!this.enabled) return;
    const key = this.config.get('POSTHOG_PERSONAL_API_KEY', { infer: true });
    const project = this.config.get('POSTHOG_PROJECT_ID', { infer: true });
    if (!key || !project) {
      this.logger.warn(
        'posthog person deletion requested but POSTHOG_PERSONAL_API_KEY / POSTHOG_PROJECT_ID are not set',
      );
      return;
    }
    try {
      const res = await fetch(`${API}/${project}/persons/bulk_delete/`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          distinct_ids: [distinctId],
          delete_events: true,
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok)
        this.logger.warn(`posthog person deletion failed: ${res.status}`);
    } catch (e) {
      this.logger.warn(
        `posthog person deletion failed: ${(e as Error).message}`,
      );
    }
  }
}
