import { dnUnder } from './adcs/ou.util';
import { ipAllowed } from './install-key.util';

export interface ApprovalRuleLike {
  id: string;
  hostGroupId: string | null;
  hostnamePattern: string | null;
  cidrs: string[];
  /** The host key passed TPM attestation (not the installer's claim). */
  requireTpm: boolean;
  /** The host showed a computer certificate from a CA the tenant trusts, not revoked. */
  requireAdcs: boolean;
  /** The host's AD distinguishedName, read from AD, is at or under this OU. */
  adOuDn: string | null;
  enabled: boolean;
}

/** What the server verified about a registering host; everything else is a claim. */
export interface VerifiedFacts {
  adcs: boolean;
  /** Read from AD this registration; null when AD was not consulted or failed. */
  adDn: string | null;
  tpm: boolean;
}

export interface RegisteringHost {
  hostGroupId: string;
  hostname: string;
  ip: string;
  verified: VerifiedFacts;
}

/**
 * A rule may auto-approve only if one of its conditions is verified by the
 * server: an address range, an AD CS certificate, an AD OU, or an attested
 * TPM. A hostname pattern is the machine's own claim, and no condition at all
 * is no check, so neither alone qualifies (F2b ruling).
 */
export function ruleHasVerifiedCondition(
  rule: Pick<
    ApprovalRuleLike,
    'cidrs' | 'requireTpm' | 'requireAdcs' | 'adOuDn'
  >,
): boolean {
  return (
    rule.cidrs.length > 0 ||
    rule.requireTpm ||
    rule.requireAdcs ||
    rule.adOuDn !== null
  );
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
 * The first enabled rule (global, or for the host's group) that has a
 * verified condition and whose every set condition matches: hostname glob,
 * address range, AD CS certificate, AD OU, attested TPM. Rules that break
 * the guard (stored before it existed) are skipped. `null` means the host
 * waits for a person (docs/hosts.md).
 */
export function matchApprovalRule<R extends ApprovalRuleLike>(
  rules: R[],
  host: RegisteringHost,
): R | null {
  return (
    rules.find(
      (rule) =>
        rule.enabled &&
        ruleHasVerifiedCondition(rule) &&
        (rule.hostGroupId === null || rule.hostGroupId === host.hostGroupId) &&
        (rule.hostnamePattern === null ||
          globMatches(rule.hostnamePattern, host.hostname)) &&
        ipAllowed(host.ip, rule.cidrs) &&
        (!rule.requireTpm || host.verified.tpm) &&
        (!rule.requireAdcs || host.verified.adcs) &&
        (rule.adOuDn === null ||
          (host.verified.adDn !== null &&
            dnUnder(host.verified.adDn, rule.adOuDn))),
    ) ?? null
  );
}
