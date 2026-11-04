/**
 * Enterprise-mode settings read from the environment. Kept here (not in env.validation.ts) while
 * the mode is behind its flag; every value has a safe default or switches its feature off.
 */
export const entConfig = () => ({
  /** Where employees open the public page and exception links. */
  consoleUrl: (
    process.env.ENT_CONSOLE_URL ?? 'https://console-manar.fixio.ae'
  ).replace(/\/+$/, ''),
  /**
   * The OIDC issuer WATCH proves identity against (the Keycloak realm with the Microsoft IdP) and
   * its public client. Unset: identity proof is off and devices stay "unverified".
   */
  watchIssuer: process.env.ENT_WATCH_OIDC_ISSUER?.replace(/\/+$/, '') || null,
  watchClientId: process.env.ENT_WATCH_OIDC_CLIENT_ID ?? 'manar-watch',
});
