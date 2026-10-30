/**
 * Policy resource patterns are prefix-only (trailing `*`). A prefix cannot say "any user's
 * ~/.ssh" or "any .env file", so each request resource also gets deterministic alias strings
 * and a rule matches when its pattern matches the raw resource or any alias.
 *
 *  - backslashes become slashes; `C:\Users\x\` , `/home/x/`, `/Users/x/`, `/root/` become `~/`
 *  - a file whose name looks like a secret also gets `secret-file:<lowercase name>`
 *  - `~/` paths also get the `secret-file:` alias when the path is under a known secret directory
 *
 * Aliases only add match candidates; a pattern that does not start with `~` or `secret-file:`
 * behaves exactly as before.
 */
const HOME_PREFIXES: readonly RegExp[] = [
  /^[a-z]:\/users\/[^/]+\//i,
  /^\/home\/[^/]+\//,
  /^\/users\/[^/]+\//i,
  /^\/root\//,
];

const SECRET_DIRS = [
  '~/.ssh/',
  '~/.aws/',
  '~/.gnupg/',
  '~/.kube/',
  '~/.azure/',
  '~/.docker/',
];
const SECRET_NAME =
  /^(\.env(\..+)?|id_(rsa|ed25519|ecdsa|dsa)|.+\.(pem|key|pfx|p12)|credentials|\.npmrc|\.netrc|\.pypirc|.+\.tfstate)$/i;

export function resourceAliases(resource: string): string[] {
  const aliases = new Set<string>();
  let path = resource.replace(/\\/g, '/');
  if (path.startsWith('~')) {
    path = path.replace(/^~(?=\/|$)/, '~');
  } else {
    for (const re of HOME_PREFIXES) {
      if (re.test(path)) {
        path = path.replace(re, '~/');
        break;
      }
    }
  }
  // Windows folders are case-insensitive: one lower-case form for drive paths outside home.
  if (/^[a-z]:\//i.test(path)) path = path.toLowerCase();
  if (path !== resource) aliases.add(path);
  const name = path.slice(path.lastIndexOf('/') + 1);
  const lowered = path.toLowerCase();
  if (
    !/\s/.test(path) &&
    (SECRET_NAME.test(name) || SECRET_DIRS.some((d) => lowered.startsWith(d)))
  ) {
    aliases.add(`secret-file:${name.toLowerCase()}`);
  }
  return [...aliases];
}
