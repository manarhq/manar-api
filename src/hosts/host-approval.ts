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

/** `*` any run, `?` one character; everything else literal; whole name, any case. */
function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `^${escaped.replace(/\*/g, '.*').replace(/\?/g, '.')}$`,
    'i',
  );
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
          globToRegExp(rule.hostnamePattern).test(host.hostname)) &&
        ipAllowed(host.ip, rule.cidrs) &&
        (!rule.requireTpm || host.keyType === 'TPM'),
    ) ?? null
  );
}
