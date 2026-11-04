import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);
const flag = z.enum(['true', 'false']).optional();
const int = (min: number, max: number) =>
  z.preprocess(
    (v) => (typeof v === 'string' && v.trim() ? Number(v) : undefined),
    z.number().int().min(min).max(max).optional(),
  );

/**
 * Growth track (badge, weekly digest, invites, account deletion). Secrets
 * (MANAR_LINK_SECRET, ACS_EMAIL_CONNECTION_STRING) come from ExternalSecrets. Without the link
 * secret nothing signed (invites, unsubscribe, cancel links) is issued or accepted; without the
 * ACS string nothing is emailed. Every key is optional (like the auth settings) so existing
 * fixtures keep validating; `growthSetting` supplies the defaults.
 */
export const GrowthConfigSchema = z.object({
  /** HMAC key for signed links, at least 32 characters. */
  MANAR_LINK_SECRET: optional.pipe(z.string().min(32).optional()),
  /** `endpoint=https://<name>.communication.azure.com/;accesskey=<base64>` */
  ACS_EMAIL_CONNECTION_STRING: optional,
  MAIL_FROM: optional.pipe(z.string().email().optional()),
  MAIL_REPLY_TO: optional.pipe(z.string().email().optional()),
  WEEKLY_DIGEST_ENABLED: flag,
  ACCOUNT_DELETION_GRACE_DAYS: int(1, 30),
  INVITE_TTL_DAYS: int(1, 30),
  /** Public community link; the web and landing read their own copy of it. */
  MANAR_DISCORD_URL: optional,
});

const DEFAULTS = {
  MAIL_FROM: 'noreply@fixio.ae',
  MAIL_REPLY_TO: 'support@fixio.ae',
  WEEKLY_DIGEST_ENABLED: 'true',
  ACCOUNT_DELETION_GRACE_DAYS: 7,
  INVITE_TTL_DAYS: 7,
} as const;

/** One growth setting with its default. */
export function growthSetting<K extends keyof typeof DEFAULTS>(
  config: { get(key: K, opts: { infer: true }): unknown },
  key: K,
): (typeof DEFAULTS)[K] extends number ? number : string {
  return (config.get(key, { infer: true }) ?? DEFAULTS[key]) as never;
}
