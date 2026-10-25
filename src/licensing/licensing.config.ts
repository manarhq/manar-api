import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * Signed offline licence (docs/licensing.md). Both sources are optional and a bad or missing
 * licence never stops the API: it only changes the reported status. MANAR_LICENSE_FILE wins when
 * both are set.
 */
export const LicensingConfigSchema = z.object({
  /** Path to the licence JWS, typically a mounted Secret. Re-read on change and every hour. */
  MANAR_LICENSE_FILE: optional,
  /** The licence JWS inline. */
  MANAR_LICENSE: optional,
  /**
   * What this deployment is when no verified licence says so. A hosted deployment without a
   * licence shows tenants no banner; a customer one does.
   */
  MANAR_DEPLOYMENT: z.enum(['hosted', 'customer']).default('customer'),
});

export type LicensingConfig = z.infer<typeof LicensingConfigSchema>;
