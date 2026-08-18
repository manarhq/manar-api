/**
 * Phase 9a (Section 47 — "be precise here"). `AuditEvent.eventHash` must be
 * deterministic regardless of the key insertion order any particular call
 * site happened to construct its `data`/`actor` object in. Plain
 * `JSON.stringify` explicitly preserves insertion order for string keys
 * (ECMA-262 `[[OwnPropertyKeys]]`/`JSON.stringify` ordering) — relying on
 * that would make the hash chain a hidden dependency on *how* an event
 * object happens to be built today. A future refactor that reorders how,
 * say, `AuthorizationService` constructs its `data` payload (e.g. moving a
 * field assignment earlier) would then silently change every new event's
 * hash relative to what an external verifier expects, with no compiler
 * error and no obviously-related test failure anywhere near that refactor.
 *
 * `canonicalize` sidesteps this entirely: every plain object's keys are
 * sorted (recursively, so nested objects at any depth are covered) before
 * serialization, so two structurally-identical objects with differently
 * ordered keys always canonicalize to byte-identical output — a real,
 * enforced invariant (see `canonical-json.spec.ts`), not just a convention
 * callers are trusted to follow. Arrays are never reordered — array order
 * is semantically significant in this codebase's event data (e.g.
 * first-match-wins policy rule lists — `docs/policy-model.md`), unlike
 * object key order, which is never significant.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(toCanonicalForm(value));
}

/**
 * Recursively rebuilds `value` with every plain object's keys sorted
 * lexicographically (`Array.prototype.sort`'s default UTF-16 code-unit
 * comparison — the same deterministic ordering regardless of locale/
 * environment, unlike `localeCompare`). Numbers and strings are passed
 * through unchanged: `JSON.stringify`'s own number formatting is already
 * fully deterministic for finite numbers (no engine-dependent variation for
 * the same input value), and string formatting/escaping is likewise fixed
 * by the JSON spec — there is no ambiguity for `canonicalize` to remove
 * there, only in *key order*.
 *
 * `Date` instances are normalized to their ISO-8601 string form explicitly
 * — `JSON.stringify` would do this anyway via `Date.prototype.toJSON`, but
 * making it explicit here means a `Date` embedded anywhere inside a nested
 * `data` object is canonicalized identically whether or not it happens to
 * reach `JSON.stringify` directly.
 */
function toCanonicalForm(value: unknown): unknown {
  if (value === null || value === undefined) {
    return null;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Array.isArray(value)) {
    return value.map((entry) => toCanonicalForm(entry));
  }
  if (typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const sortedKeys = Object.keys(source).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      const entry = source[key];
      // Match JSON.stringify's own behavior: a key whose value is
      // `undefined` is omitted entirely from the canonical form, never
      // serialized as `null` (which would be indistinguishable from an
      // explicit `null` value at that key).
      if (entry === undefined) continue;
      result[key] = toCanonicalForm(entry);
    }
    return result;
  }
  // string | number | boolean — deterministic under JSON.stringify already.
  return value;
}
