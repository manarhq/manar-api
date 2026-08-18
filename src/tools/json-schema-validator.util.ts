import Ajv from 'ajv';
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
 * One shared, module-level `Ajv` instance: compiled-schema caching is
 * `ajv`'s own documented performance recommendation, and every call site
 * in this phase (`HttpToolAdapter`/`McpToolAdapter`) validates against a
 * schema freshly loaded from the database on every invocation anyway, so
 * there's no cross-tenant/cross-tool cache-poisoning concern — a schema is
 * only ever compiled against the exact JSON object stored in that specific
 * `ToolAction.inputSchema` at call time.
 */
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

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

  let validate: ReturnType<typeof ajv.compile>;
  try {
    validate = ajv.compile(schema);
  } catch (error) {
    return {
      valid: false,
      errors: `inputSchema is not a valid JSON Schema: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }

  const valid = validate(data);
  if (valid) return { valid: true };

  const errors = (validate.errors ?? [])
    .map((e) => `${e.instancePath || '(root)'} ${e.message ?? ''}`.trim())
    .join('; ');
  return { valid: false, errors: errors || 'input failed schema validation' };
}
