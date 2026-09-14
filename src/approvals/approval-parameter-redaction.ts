/**
 * Release 2026-11-11 (brief §3.4) — rendering an `ApprovalRequest.params`
 * snapshot for a human reviewer.
 *
 * ## Why this exists
 *
 * The approval mechanism binds a grant to an exact parameter snapshot
 * (`computeParameterHash`), and that binding is genuinely strong: a
 * one-use grant, an atomic conditional redemption, a kill-switch recheck.
 * But the human approving it was never shown the parameters. An approver
 * reviewing `iam/disable-user` on `user-7` could not see
 * `{ scope: "all-sessions", cascade: true }`. They approved, and the grant
 * was cryptographically bound to values they had never read.
 *
 * A binding to an unreviewed snapshot is a weaker control than it looks,
 * which is exactly the kind of gap brief §3.4 is aimed at: the reviewer
 * must receive the exact action under review.
 *
 * ## What this does and — more importantly — what it does not
 *
 * Redaction here is **key-name based**. A value is withheld when its key
 * looks like a credential (`password`, `token`, `secret`, `apiKey`,
 * `authorization`, `privateKey`, `credential`, and similar). It is
 * deliberately *not* content-based pattern matching.
 *
 * That is a real limitation and it is stated rather than papered over.
 * A secret placed under an innocuous key — `{ note: "the root password is
 * hunter2" }` — is **not** redacted by this function. Two reasons for
 * accepting that:
 *
 *  1. Content detection is manar-ai's job, and this codebase deliberately
 *     refuses to implement DLP pattern matching in two places (see
 *     `src/tools/dlp-redaction.util.ts`'s doc comment for the same call
 *     made for tool results). A second, weaker detector here would drift
 *     from the real one and create false confidence.
 *  2. The primary control on this surface is authorization, not redaction.
 *     This data is reachable only through the JWT human surface, gated to
 *     `APPROVER`/`SECURITY_ADMIN`/`TENANT_OWNER`. It is never reachable by
 *     an agent, which uses a physically separate mTLS listener.
 *
 * So: treat this as *hygiene for the obvious case*, and as a way to keep
 * credentials out of screenshots and shoulder-surfing range — not as a
 * guarantee that no sensitive value reaches an authorized reviewer's
 * screen. A reviewer who must see a parameter to judge the action is the
 * point of the feature.
 *
 * ## Why redacted keys are listed rather than silently dropped
 *
 * A reviewer who cannot tell that something was withheld will read a
 * partial object as a complete one. `redactedKeyPaths` names every
 * withheld location so the reviewer knows the difference between "this
 * action has no credential parameter" and "it has one and you are not
 * being shown it".
 */

/** The rendered snapshot handed to a human reviewer. */
export interface RedactedParameters {
  /** The parameter structure with credential-shaped values replaced by `REDACTED_PLACEHOLDER`. */
  params: unknown;
  /**
   * Dotted paths of every value that was withheld, in traversal order
   * (array elements appear as `items.0.token`). Empty when nothing was
   * redacted — which is a meaningful, positive statement.
   */
  redactedKeyPaths: string[];
  /**
   * True when traversal stopped early because the structure exceeded
   * `MAX_DEPTH` or `MAX_NODES`. The reviewer must be told that what they
   * are looking at is incomplete; a silently pruned object would be worse
   * than no object.
   */
  truncated: boolean;
}

export const REDACTED_PLACEHOLDER = '[redacted]';

/**
 * Key-name fragments that mark a value as credential-shaped. Matched
 * case-insensitively against the key with non-alphanumerics stripped, so
 * `api_key`, `apiKey`, `API-KEY` and `apikey` all match one entry.
 */
const CREDENTIAL_KEY_FRAGMENTS = [
  'password',
  'passwd',
  'secret',
  'token',
  'apikey',
  'accesskey',
  'privatekey',
  'credential',
  'authorization',
  'auth',
  'session',
  'cookie',
  'signature',
  'certificate',
];

/** Bounded traversal: a hostile or merely huge params object must not be able to make this expensive or to blow the stack. */
const MAX_DEPTH = 12;
const MAX_NODES = 2_000;

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** True when this key name indicates the value is a credential. */
export function isCredentialKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return CREDENTIAL_KEY_FRAGMENTS.some((fragment) =>
    normalized.includes(fragment),
  );
}

/**
 * Produces the reviewer-facing view of a stored `params` value.
 *
 * Structure is preserved: an approver needs to see *that* a `cascade` flag
 * exists and is `true`, which is precisely the kind of parameter that
 * changes what an action does. Only credential-shaped leaves are replaced.
 */
export function redactApprovalParameters(params: unknown): RedactedParameters {
  const redactedKeyPaths: string[] = [];
  let nodes = 0;
  let truncated = false;

  function walk(value: unknown, path: string, depth: number): unknown {
    nodes += 1;
    if (depth > MAX_DEPTH || nodes > MAX_NODES) {
      truncated = true;
      return REDACTED_PLACEHOLDER;
    }

    if (Array.isArray(value)) {
      return value.map((entry, index) =>
        walk(
          entry,
          path === '' ? String(index) : `${path}.${index}`,
          depth + 1,
        ),
      );
    }

    if (value !== null && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [key, entry] of Object.entries(
        value as Record<string, unknown>,
      )) {
        const childPath = path === '' ? key : `${path}.${key}`;
        if (isCredentialKey(key)) {
          // Withheld whatever the value's type — an object under a
          // `credentials` key is not safer than a string under one.
          redactedKeyPaths.push(childPath);
          out[key] = REDACTED_PLACEHOLDER;
          continue;
        }
        out[key] = walk(entry, childPath, depth + 1);
      }
      return out;
    }

    return value;
  }

  return {
    params: walk(params, '', 0),
    redactedKeyPaths,
    truncated,
  };
}
