import { createHash } from 'node:crypto';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';

/**
 * `ToolAction.inputSchema` is stored as plain JSON Schema (not a
 * serialized Zod schema — Zod schemas aren't JSON-serializable, and JSON
 * Schema is the interoperable, storable, tool-vendor-agnostic choice; see
 * docs/tool-gateway.md). `ajv` is the de facto standard JSON Schema
 * validator for Node (also a transitive dependency of
 * `@modelcontextprotocol/sdk` itself, for the same reason) — a real
 * validator, not a hand-rolled subset-of-JSON-Schema checker.
 *
 * One shared, module-level `Ajv` instance. `ToolAction.inputSchema` arrives as a fresh object
 * on every call, and Ajv caches compiled schemas by object identity, so compiling per call
 * grew memory with every invocation and broke on a second call for any schema with an `$id`.
 * Validators are therefore compiled once per distinct schema, keyed by a hash of its canonical
 * JSON, in a bounded LRU. `addUsedSchema: false` keeps `$id`s out of Ajv's global registry, and
 * an evicted schema is removed from Ajv's own cache too.
 */
const ajv = new Ajv({ allErrors: true, strict: false, addUsedSchema: false });
addFormats(ajv);

/** Distinct schemas kept compiled. Far above any tenant's real catalogue; bounds memory under churn. */
export const VALIDATOR_CACHE_MAX = 500;

type CompiledEntry =
  | { schema: object; validate: ValidateFunction }
  | { schema: object; compileError: string };

const compiled = new Map<string, CompiledEntry>();

/** JSON with object keys sorted, so `{a,b}` and `{b,a}` hash alike. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map(
        (k) =>
          `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`,
      )
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function compiledFor(schema: object): CompiledEntry {
  const key = createHash('sha256').update(canonicalJson(schema)).digest('hex');
  const hit = compiled.get(key);
  if (hit) {
    // Map keeps insertion order: re-inserting marks this entry most recently used.
    compiled.delete(key);
    compiled.set(key, hit);
    return hit;
  }
  let entry: CompiledEntry;
  try {
    entry = { schema, validate: ajv.compile(schema) };
  } catch (error) {
    ajv.removeSchema(schema);
    entry = {
      schema,
      compileError: error instanceof Error ? error.message : String(error),
    };
  }
  compiled.set(key, entry);
  if (compiled.size > VALIDATOR_CACHE_MAX) {
    const [oldestKey, oldest] = compiled.entries().next().value as [
      string,
      CompiledEntry,
    ];
    compiled.delete(oldestKey);
    ajv.removeSchema(oldest.schema);
  }
  return entry;
}

/** For tests: how many validators are held. */
export function validatorCacheSize(): number {
  return compiled.size;
}

export interface SchemaValidationResult {
  valid: boolean;
  /** Human-readable, joined error summary — present only when `valid` is `false`. Never includes `data` itself (which may be an agent-supplied `params` payload of arbitrary shape). */
  errors?: string;
}

/**
 * Validates `data` against `schema` (a plain JSON Schema object, or
 * `null`/`undefined` for "no schema declared -- skip validation
 * entirely"). Manar owns this validation boundary itself — never trusts
 * the target tool (HTTP or MCP) to reject a malformed call, the same
 * "Manar owns policy, the external system only does the mechanical
 * operation" posture `CertificateAuthorityService`/`OpenBaoPkiClient`
 * establish for PKI (see docs/agent-identity.md).
 */
export function validateAgainstSchema(
  schema: unknown,
  data: unknown,
): SchemaValidationResult {
  if (schema == null) return { valid: true };

  if (typeof schema !== 'object' && typeof schema !== 'boolean') {
    return { valid: false, errors: 'inputSchema is not a valid JSON Schema' };
  }
  if (typeof schema === 'boolean') {
    return schema
      ? { valid: true }
      : { valid: false, errors: 'input failed schema validation' };
  }
  const entry = compiledFor(schema);
  if ('compileError' in entry) {
    return {
      valid: false,
      errors: `inputSchema is not a valid JSON Schema: ${entry.compileError}`,
    };
  }
  const validate = entry.validate;

  const valid = validate(data);
  if (valid) return { valid: true };

  const errors = (validate.errors ?? [])
    .map((e) => `${e.instancePath || '(root)'} ${e.message ?? ''}`.trim())
    .join('; ');
  return { valid: false, errors: errors || 'input failed schema validation' };
}
