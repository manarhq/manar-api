/**
 * Distinguished names (RFC 4514) for OU mapping. Comparison is by RDN, case
 * insensitive, ignoring spaces around `,` and `=`; escaped commas stay inside
 * their value. A DN that cannot be split cleanly is rejected (null), so a
 * malformed value never matches a rule.
 */
export function splitDn(dn: string): string[] | null {
  const rdns: string[] = [];
  let current = '';
  for (let i = 0; i < dn.length; i += 1) {
    const ch = dn[i]!;
    if (ch === '\\') {
      if (i + 1 >= dn.length) return null;
      current += ch + dn[i + 1]!;
      i += 1;
    } else if (ch === ',') {
      rdns.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  rdns.push(current);
  const out: string[] = [];
  for (const rdn of rdns) {
    const eq = rdn.indexOf('=');
    if (eq < 1) return null;
    const type = rdn.slice(0, eq).trim().toLowerCase();
    const value = rdn
      .slice(eq + 1)
      .trim()
      .toLowerCase();
    if (!type || !value) return null;
    out.push(`${type}=${value}`);
  }
  return out;
}

/** The DN in a comparable form, or null when malformed. */
export function normalizeDn(dn: string): string | null {
  return splitDn(dn)?.join(',') ?? null;
}

/** Whether `dn` is `suffix` itself or sits anywhere below it. */
export function dnUnder(dn: string, suffix: string): boolean {
  const a = splitDn(dn);
  const b = splitDn(suffix);
  if (!a || !b || b.length > a.length) return false;
  return b.every((rdn, i) => rdn === a[a.length - b.length + i]);
}

/** The rule with the longest matching suffix wins; null when none matches. */
export function longestOuMatch<R extends { ouDn: string }>(
  dn: string,
  rules: R[],
): R | null {
  let best: R | null = null;
  let bestLen = -1;
  for (const rule of rules) {
    const len = splitDn(rule.ouDn)?.length ?? -1;
    if (len > bestLen && dnUnder(dn, rule.ouDn)) {
      best = rule;
      bestLen = len;
    }
  }
  return best;
}

/** RFC 4515 escaping of an assertion value in a filter. */
export function escapeLdapFilter(value: string): string {
  return value.replace(
    /[\\*()\0]/g,
    (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`,
  );
}
