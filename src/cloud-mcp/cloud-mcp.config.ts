import type { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { AppConfig } from '../config/env.validation';

const DNS_NAME =
  /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** Client ids Manar gives pre-registered (Copilot Studio) clients. */
export const PRE_REGISTERED_CLIENT_PREFIX = 'manar-cloud-';
/** Token claim the agent scope's role mapper writes the user's agent role into. */
export const AGENT_ROLE_CLAIM = 'manar_roles';

/**
 * Public MCP endpoint for cloud agents (docs/cloud-agents.md). Off by default: with
 * `MANAR_MCP_ENABLED` unset or false the `/mcp/*` and protected resource metadata routes answer
 * 404 and cloud agents cannot be connected. All optional; defaults are applied by
 * `cloudMcpSettings`.
 */
export const CloudMcpConfigSchema = z.object({
  MANAR_MCP_ENABLED: z.enum(['true', 'false']).optional(),
  /** Public host of the endpoint, e.g. `mcp.manar.example.com`. MCP URLs are `https://<host>/mcp/<tenant>/<agent>`. */
  MANAR_MCP_HOST: z.preprocess(
    // An empty value (the chart default) means unset.
    (value) => (value === '' ? undefined : value),
    z
      .string()
      .regex(/^[a-z0-9.-]+(:\d+)?$/, 'a host name, no scheme or path')
      .optional(),
  ),
  /**
   * Redirect URI hosts a self-registering client (DCR, ChatGPT) may use; written to the realm's
   * anonymous Trusted Hosts policy when a ChatGPT agent is connected. Comma-separated, default
   * `chatgpt.com`.
   */
  MANAR_MCP_DCR_TRUSTED_HOSTS: z
    .string()
    .refine(
      (value) =>
        value
          .split(',')
          .map((host) => host.trim())
          .every((host) => host === '' || DNS_NAME.test(host)),
      'comma-separated plain host names (no scheme, port, path or wildcard)',
    )
    .optional(),
  /**
   * Issuer of the shared hosted realm (`https://auth-manar.vax.sh/realms/manar`). Tenants with no
   * realm of their own connect their cloud agents there. Unset: such tenants cannot connect any.
   */
  MANAR_MCP_SHARED_ISSUER: z.preprocess(
    (value) => (value === '' ? undefined : value),
    z.string().url().optional(),
  ),
  /**
   * ChatGPT (dynamic client registration) on the shared realm. On by default (hardening proven in
   * test/cloud-mcp-shared-chatgpt.e2e-spec.ts); `false` closes it. Per-tenant realms are not
   * affected.
   */
  MANAR_MCP_CHATGPT_ENABLED: z.enum(['true', 'false']).optional(),
  /** Requests per cloud agent per minute, all MCP methods (default 60). */
  MANAR_MCP_RATE_LIMIT_PER_MINUTE: z.coerce
    .number()
    .int()
    .positive()
    .optional(),
  /** Largest accepted request body in bytes (default 256 KiB, at most 1 MiB); bigger is 413. */
  MANAR_MCP_MAX_BODY_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .max(1_048_576)
    .optional(),
});

export type CloudMcpConfig = z.infer<typeof CloudMcpConfigSchema>;

export function cloudMcpConfigIssues(config: CloudMcpConfig): string[] {
  return config.MANAR_MCP_ENABLED === 'true' && !config.MANAR_MCP_HOST
    ? ['MANAR_MCP_HOST: required when MANAR_MCP_ENABLED is true']
    : [];
}

export interface CloudMcpSettings {
  /** Null when the endpoint is off. */
  host: string | null;
  dcrTrustedHosts: string[];
  /** Shared realm issuer without a trailing slash, or null. */
  sharedIssuer: string | null;
  chatGptOnSharedRealm: boolean;
  ratePerMinute: number;
  maxBodyBytes: number;
}

export function cloudMcpSettings(
  config: ConfigService<AppConfig, true>,
): CloudMcpSettings {
  const get = <K extends keyof CloudMcpConfig>(key: K) =>
    config.get(key, { infer: true });
  return {
    host:
      get('MANAR_MCP_ENABLED') === 'true'
        ? (get('MANAR_MCP_HOST') ?? null)
        : null,
    dcrTrustedHosts: (get('MANAR_MCP_DCR_TRUSTED_HOSTS') ?? 'chatgpt.com')
      .split(',')
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
    sharedIssuer: get('MANAR_MCP_SHARED_ISSUER')?.replace(/\/+$/, '') ?? null,
    chatGptOnSharedRealm: get('MANAR_MCP_CHATGPT_ENABLED') !== 'false',
    ratePerMinute: get('MANAR_MCP_RATE_LIMIT_PER_MINUTE') ?? 60,
    maxBodyBytes: get('MANAR_MCP_MAX_BODY_BYTES') ?? 262_144,
  };
}

/** The canonical MCP URL of one cloud agent: the token audience and the protected resource. */
export function cloudMcpResourceUrl(
  host: string,
  tenantSlug: string,
  agentSlug: string,
): string {
  return `https://${host}/mcp/${tenantSlug}/${agentSlug}`;
}

/** RFC 9728 metadata URL for a resource URL (path-suffixed form, MCP spec discovery order). */
export function cloudMcpMetadataUrl(
  host: string,
  tenantSlug: string,
  agentSlug: string,
): string {
  return `https://${host}/.well-known/oauth-protected-resource/mcp/${tenantSlug}/${agentSlug}`;
}

/** Token claim the shared realm's agent scope stamps with the tenant id. */
export const TENANT_CLAIM = 'manar_tenant';

/**
 * The Keycloak client scope that puts one agent's MCP URL in the token audience. On the shared
 * realm the name carries the tenant id, so two tenants never collide.
 */
export function cloudMcpScope(agentSlug: string, tenantId?: string): string {
  return tenantId
    ? `manar-mcp-${tenantId}-${agentSlug}`
    : `manar-mcp-${agentSlug}`;
}

/** Pre-registered client id of an agent (shared realm: tenant id in the name). */
export function cloudMcpClientId(agentSlug: string, tenantId?: string): string {
  return tenantId
    ? `${PRE_REGISTERED_CLIENT_PREFIX}${tenantId}-${agentSlug}`
    : `${PRE_REGISTERED_CLIENT_PREFIX}${agentSlug}`;
}

/** Realm role a person needs to use one cloud agent (per-tenant realms only; assigned by the tenant admin). */
export function cloudMcpRole(agentSlug: string): string {
  return `manar-agent-${agentSlug}`;
}

/** Routes of the public endpoint (they are not part of the human API's rate limit). */
export function isCloudMcpPath(url: string): boolean {
  return (
    url.startsWith('/mcp/') ||
    url.startsWith('/.well-known/oauth-protected-resource/mcp/')
  );
}

/** Client attribute: 'pending' (waiting for an admin) or 'confirmed'. The sweep never touches either. */
export const DCR_STATE_ATTRIBUTE = 'manar.dcr.state';
/** Client attribute: epoch ms the sweep first saw an unconfirmed self-registered client. */
export const DCR_FIRST_SEEN_ATTRIBUTE = 'manar.dcr.first_seen';
