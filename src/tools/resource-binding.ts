/**
 * JSON Schema keyword an HTTP or MCP action's `inputSchema` uses to name the
 * top-level param that carries the action's real target, e.g.
 * `{ "type": "object", "x-manar-resource-param": "hostId", ... }`.
 *
 * Authorization, policy rules and approvals decide on the request's
 * `resource`. For typed connectors (Microsoft, GitLab) the adapter builds the
 * call from `resource` itself. HTTP and MCP tools receive `resource` next to
 * free-form `params`, so without this keyword a tool that reads its target
 * from `params` can act on something other than what was decided. With it,
 * the named param must equal `resource` (or is filled in from it).
 */
export const RESOURCE_PARAM_KEYWORD = 'x-manar-resource-param';

export type ResourceBinding =
  { ok: true; params: unknown } | { ok: false; errorMessage: string };

export function bindResourceToParams(
  inputSchema: unknown,
  resource: string,
  params: unknown,
): ResourceBinding {
  const name =
    inputSchema !== null && typeof inputSchema === 'object'
      ? (inputSchema as Record<string, unknown>)[RESOURCE_PARAM_KEYWORD]
      : undefined;
  if (typeof name !== 'string' || name === '') return { ok: true, params };

  const fields =
    params === undefined || params === null
      ? {}
      : typeof params === 'object' && !Array.isArray(params)
        ? (params as Record<string, unknown>)
        : null;
  if (fields === null) {
    return { ok: false, errorMessage: 'resource_param_mismatch' };
  }
  if (!Object.hasOwn(fields, name)) {
    return { ok: true, params: { ...fields, [name]: resource } };
  }
  return fields[name] === resource
    ? { ok: true, params }
    : { ok: false, errorMessage: 'resource_param_mismatch' };
}
