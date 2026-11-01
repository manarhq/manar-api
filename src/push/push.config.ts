import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * Web Push (spec 4.6). The VAPID key pair comes from the secret store (ExternalSecret keys
 * `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT`). Without all three, push is off:
 * subscriptions are refused and nothing is sent, and the console says so. Generate a pair with
 * `npx web-push generate-vapid-keys`.
 */
export const PushConfigSchema = z.object({
  VAPID_PUBLIC_KEY: optional,
  VAPID_PRIVATE_KEY: optional,
  /** `mailto:` or `https:` contact for push services. */
  VAPID_SUBJECT: optional,
});

export type PushConfig = z.infer<typeof PushConfigSchema>;

export function pushConfigIssues(c: PushConfig): string[] {
  const set = [c.VAPID_PUBLIC_KEY, c.VAPID_PRIVATE_KEY, c.VAPID_SUBJECT].filter(
    Boolean,
  ).length;
  if (set === 0 || set === 3) {
    if (set === 3 && !/^(mailto:|https:\/\/)/.test(c.VAPID_SUBJECT as string))
      return ['VAPID_SUBJECT must start with mailto: or https://'];
    return [];
  }
  return [
    'VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY and VAPID_SUBJECT must be set together',
  ];
}
