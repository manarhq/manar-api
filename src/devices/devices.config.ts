import { z } from 'zod';

const optional = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);
const https = z.url().refine((u) => u.startsWith('https://'), 'an https URL');
const sha256 = optional.pipe(
  z
    .string()
    .regex(/^[0-9a-f]{64}$/, '64 lower-case hex characters (from SHA256SUMS)')
    .optional(),
);

/**
 * The "Add device" one-liner (docs/hosts.md). Everything here is public information: the
 * script embeds the release version and the checksums, never a secret. No release configured
 * means `/i/<code>` answers with a script that says the installer is not available yet.
 */
export const DevicesConfigSchema = z.object({
  /** Public base URL of the API as devices reach it (the `/i/<code>` host). */
  MANAR_CONSOLE_URL: https.optional(),
  /** The mTLS listener devices use after enrolling. */
  MANAR_HOST_URL: https.optional(),
  /** Release tag of manar-edge the scripts install, e.g. `v0.1.0`. */
  MANAR_EDGE_VERSION: optional.pipe(
    z
      .string()
      .regex(/^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/, 'a release tag like v0.1.0')
      .optional(),
  ),
  MANAR_EDGE_RELEASE_BASE: https.optional(),
  /** SHA-256 of each binary, from the release's SHA256SUMS. */
  MANAR_EDGE_SHA256_WINDOWS_AMD64: sha256,
  MANAR_EDGE_SHA256_LINUX_AMD64: sha256,
  MANAR_EDGE_SHA256_LINUX_ARM64: sha256,
  /**
   * Server secret for the HMAC that stores install keys and short codes (see hashInstallKey).
   * Secret: delivered by ExternalSecret into the `secrets.name` Secret as
   * MANAR_INSTALL_KEY_HMAC_SECRET. Required in production.
   */
  MANAR_INSTALL_KEY_HMAC_SECRET: optional.pipe(z.string().min(32).optional()),
});

export function devicesConfigIssues(c: {
  NODE_ENV?: string;
  MANAR_INSTALL_KEY_HMAC_SECRET?: string;
}): string[] {
  return c.NODE_ENV === 'production' && !c.MANAR_INSTALL_KEY_HMAC_SECRET
    ? [
        'MANAR_INSTALL_KEY_HMAC_SECRET: required in production (at least 32 characters, from the secret store)',
      ]
    : [];
}

export type DevicesConfig = z.infer<typeof DevicesConfigSchema>;

/** Used when the variable is unset (the hosted install). */
export const DEVICES_DEFAULTS = {
  MANAR_CONSOLE_URL: 'https://console-manar.fixio.ae',
  MANAR_HOST_URL: 'https://agents-manar.fixio.ae:3443',
  MANAR_EDGE_RELEASE_BASE:
    'https://github.com/manarhq/manar-edge/releases/download',
} as const;
