import { createHash } from 'node:crypto';
import { dump as dumpYaml, load as loadYaml } from 'js-yaml';
import { PolicyContent, PolicyContentSchema } from './policy-content.schema';

/**
 * YAML⇄JSON round-trip + deterministic content-hashing for `PolicyVersion`
 * (Section 21 — "GUI/YAML/JSON must manipulate the same underlying model";
 * there is no GUI yet, Phase 11, but the management API must not be
 * JSON-only). Pure, dependency-free of Prisma/Nest (same "no I/O, kept
 * trivially unit-testable" convention as
 * `src/authorization/grant-triples.ts`) other than `js-yaml`, the YAML 1.2
 * parser/serializer this codebase pulls in for exactly this purpose (see
 * docs/policy-model.md for why: current, actively maintained, ships its
 * own TypeScript types, and — since v4 — `load()` is the safe parser by
 * default, no separate "safeLoad" API to remember to use).
 */

/** Parses a YAML document into a validated `PolicyContent` — throws (via Zod) if the parsed structure doesn't match `PolicyContentSchema`, same fail-closed posture as `parsePolicyContent`. */
export function parsePolicyContentYaml(yamlText: string): PolicyContent {
  const parsed: unknown = loadYaml(yamlText);
  return PolicyContentSchema.parse(parsed);
}

/** Serializes a validated `PolicyContent` back to a YAML document — the inverse of `parsePolicyContentYaml`, used by `GET /policies/:id/versions/:versionId?format=yaml`. */
export function dumpPolicyContentYaml(content: PolicyContent): string {
  return dumpYaml(content, { noRefs: true, sortKeys: false });
}

/**
 * Recursively sorts every plain object's keys (arrays keep their original
 * order — order is semantically significant there, per "first-match-wins")
 * so two structurally-equal values that merely differ in *key order*
 * (e.g. a hand-written YAML document vs. a JSON `POST` body for the exact
 * same policy) serialize to byte-identical JSON. This is a deliberately
 * minimal canonicalization — not a full RFC 8785 (JSON Canonicalization
 * Scheme) implementation — sufficient for `PolicyContent`'s shape (nested
 * plain objects/arrays/strings/numbers/booleans/null; no need for RFC
 * 8785's I-JSON number-formatting edge cases here, since `PolicyContent`
 * only ever contains integers/simple decimals produced by this codebase's
 * own Zod schemas, never arbitrary externally-signed numeric input).
 */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
    );
    const sorted: Record<string, unknown> = {};
    for (const [key, val] of entries) {
      sorted[key] = canonicalize(val);
    }
    return sorted;
  }
  return value;
}

/**
 * sha256 hex of `content`'s canonical JSON serialization — identical for
 * any two structurally-equal `PolicyContent` values regardless of key
 * order, so a YAML submission and its JSON equivalent produce the exact
 * same `PolicyVersion.contentHash` (see
 * `src/policy/policy-content-codec.spec.ts`). Same `createHash('sha256')`
 * pattern `src/authorization/openfga-object-id.util.ts`'s `shortHash`
 * already establishes elsewhere in this codebase.
 */
export function computeContentHash(content: unknown): string {
  const canonicalJson = JSON.stringify(canonicalize(content));
  return createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
}

/**
 * Resolves a `CreatePolicyRequest`/`CreatePolicyVersionRequest` body's
 * `content` (already-parsed JSON) or `contentYaml` (a YAML document
 * string) into a single validated `PolicyContent` — the one place both
 * input formats converge before anything is ever written to a
 * `PolicyVersion` row, so JSON and YAML submissions share the exact same
 * validation/error path (Section 21). Throws (via Zod, same as
 * `parsePolicyContent`/`parsePolicyContentYaml`) on malformed content in
 * either format; the caller (`PolicyController`, via `parseBodyOrThrow`'s
 * sibling convention) maps that to a 400. Assumes exactly one of the two
 * is present — `CreatePolicyRequestSchema`/`CreatePolicyVersionRequestSchema`
 * already enforce that at the Zod-schema level before this is ever called.
 */
export function resolveSubmittedContent(body: {
  content?: unknown;
  contentYaml?: string;
}): PolicyContent {
  if (body.contentYaml !== undefined) {
    return parsePolicyContentYaml(body.contentYaml);
  }
  return PolicyContentSchema.parse(body.content);
}
