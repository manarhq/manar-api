import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * Telegram approvals bot. `TELEGRAM_BOT_TOKEN` and `TELEGRAM_WEBHOOK_SECRET` come from the secret
 * store (ExternalSecret keys); the bot name and the public webhook URL are plain config. Without a
 * token the bot is off: the webhook answers 404, link codes are refused and nothing is sent.
 * Create the bot with BotFather; the webhook secret is any 32+ random characters of [A-Za-z0-9_-].
 */
export const TelegramConfigSchema = z.object({
  TELEGRAM_BOT_TOKEN: optional,
  TELEGRAM_WEBHOOK_SECRET: optional,
  /** Without the leading `@`. */
  TELEGRAM_BOT_USERNAME: optional,
  /** Public https URL of `POST /telegram/webhook`. When set, the API registers it at start. */
  TELEGRAM_WEBHOOK_URL: optional,
});

export type TelegramConfig = z.infer<typeof TelegramConfigSchema>;

export function telegramConfigIssues(c: TelegramConfig): string[] {
  if (!c.TELEGRAM_BOT_TOKEN) return [];
  const issues: string[] = [];
  if (
    !c.TELEGRAM_WEBHOOK_SECRET ||
    !/^[A-Za-z0-9_-]{32,256}$/.test(c.TELEGRAM_WEBHOOK_SECRET)
  )
    issues.push(
      'TELEGRAM_WEBHOOK_SECRET must be 32-256 characters of A-Z a-z 0-9 _ - when TELEGRAM_BOT_TOKEN is set',
    );
  if (
    !c.TELEGRAM_BOT_USERNAME ||
    !/^[A-Za-z0-9_]{5,64}$/.test(c.TELEGRAM_BOT_USERNAME)
  )
    issues.push(
      'TELEGRAM_BOT_USERNAME is required when TELEGRAM_BOT_TOKEN is set',
    );
  if (c.TELEGRAM_WEBHOOK_URL && !c.TELEGRAM_WEBHOOK_URL.startsWith('https://'))
    issues.push('TELEGRAM_WEBHOOK_URL must be an https:// URL');
  return issues;
}
