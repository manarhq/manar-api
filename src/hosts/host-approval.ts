import { ipAllowed } from './install-key.util';

export interface ApprovalRuleLike {
  id: string;
  hostGroupId: string | null;
  hostnamePattern: string | null;
  cidrs: string[];
  requireTpm: boolean;
  enabled: boolean;
}

export interface RegisteringHost {
  hostGroupId: string;
  hostname: string;
  ip: string;
  keyType: 'TPM' | 'SOFTWARE';
}

/**
 * `*` any run, `?` one character, everything else literal; whole name, any
 * case. A linear two-pointer matcher (no regular expression), so no pattern
 * can make matching slow.
 */
export function globMatches(glob: string, name: string): boolean {
  const p = glob.toLowerCase();
  const s = name.toLowerCase();
  let pi = 0;
  let si = 0;
  let star = -1;
  let mark = 0;
  while (si < s.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === s[si])) {
      pi += 1;
      si += 1;
    } else if (pi < p.length && p[pi] === '*') {
      star = pi;
      mark = si;
      pi += 1;
    } else if (star !== -1) {
      pi = star + 1;
      mark += 1;
      si = mark;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === '*') pi += 1;
  return pi === p.length;
}

/**
 * The first enabled rule (global, or for the host's group) whose every set
 * condition matches: hostname glob, address range, TPM-backed key. `null`
 * means the host waits for a person (docs/hosts.md).
 */
export function matchApprovalRule<R extends ApprovalRuleLike>(
  rules: R[],
  host: RegisteringHost,
): R | null {
  return (
    rules.find(
      (rule) =>
        rule.enabled &&
        (rule.hostGroupId === null || rule.hostGroupId === host.hostGroupId) &&
        (rule.hostnamePattern === null ||
          globMatches(rule.hostnamePattern, host.hostname)) &&
        ipAllowed(host.ip, rule.cidrs) &&
        (!rule.requireTpm || host.keyType === 'TPM'),
    ) ?? null
  );
}
