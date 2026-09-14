import { describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { McpToolAdapter } from './mcp-tool.adapter';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/**
 * Release 2026-11-11 — regression tests for a confirmed authorization
 * bypass in the MCP adapter.
 *
 * The defect: the JSON-RPC arguments object was built as
 * `{ resource, ...params }`, spreading caller-controlled `params` after
 * the canonical, already-authorized `resource`. A caller could invoke with
 * `resource: "host-42"` and `params: { resource: "host-999" }`; Manar
 * authorized, grant-bound, invocation-recorded and audit-logged
 * **host-42**, while the MCP server received and acted on **host-999**.
 *
 * Why that is worse than an ordinary bypass: the audit chain records the
 * action Manar *authorized*, not the one it *performed*, so every
 * downstream artefact that cites the audit trail — approvals, evidence
 * exports, compliance mappings — inherits the wrong fact, and no
 * after-the-fact review can detect the discrepancy.
 *
 * `validateAgainstSchema` does not close this: stored `inputSchema` values
 * are not required to set `additionalProperties: false`, and the seeded
 * demo action ships the wide-open `{ type: 'object' }` — which is exactly
 * the schema used below.
 *
 * These tests reach `invoke()` directly with no network fake, which is
 * possible because the collision check is deliberately placed with the
 * other pure input validation, ahead of the SSRF check and the transport.
 * A test that had to stand up an MCP server to prove this would be a worse
 * test of the property.
 */

function makeAdapter(): McpToolAdapter {
  const configService = {
    // `parseSsrfAllowedHosts` expects the raw comma-separated string form;
    // empty means "no allow-list", which is the correct default for a test
    // that must never reach the network anyway.
    get: () => '',
  } as unknown as ConfigService<AppConfig, true>;
  return new McpToolAdapter(configService);
}

const tool: ToolRecord = {
  id: 'tool-1',
  name: 'edr',
  type: 'edr',
  vendor: null,
  description: null,
  // A literal loopback address, which `assertSafeOutboundUrl` rejects
  // synchronously with no DNS lookup and no socket. Two things follow:
  // these tests never touch the network, and a non-colliding call gets as
  // far as the SSRF check and stops there — so "was this rejected as a
  // collision?" stays the only thing being measured.
  baseEndpoint: 'http://127.0.0.1:9',
  protocol: 'MCP',
  credentialReference: { provider: 'ENV', reference: 'EDR_TOKEN' } as never,
  enabled: true,
  metadata: null,
} as unknown as ToolRecord;

const action: ToolActionRecord = {
  id: 'action-1',
  toolId: 'tool-1',
  name: 'isolate-host',
  description: null,
  // The wide-open schema the demo seed actually ships.
  inputSchema: { type: 'object' } as never,
  mutating: true,
  destructive: true,
  classification: 'INTERNAL',
} as unknown as ToolActionRecord;

describe('McpToolAdapter — reserved argument collision', () => {
  it('refuses a call whose params would override the authorized resource', async () => {
    const adapter = makeAdapter();

    const result = await adapter.invoke(
      tool,
      action,
      'host-42',
      { resource: 'host-999' },
      'credential',
    );

    expect(result.success).toBe(false);
    expect(result.errorMessage).toContain('reserved argument name');
    // The rejected value must not appear in the message returned to the
    // caller's agent — the error explains the rule, it does not echo back
    // an attacker-chosen string.
    expect(result.errorMessage).toContain('resource');
  });

  it('refuses before attempting any outbound connection', async () => {
    const adapter = makeAdapter();

    // A non-colliding call to this endpoint stops at the SSRF check and
    // returns `blocked_by_outbound_url_policy`. Asserting the colliding
    // call returns neither that nor a transport error proves the refusal
    // happened earlier, during pure input validation.
    const result = await adapter.invoke(
      tool,
      action,
      'host-42',
      { resource: 'host-999' },
      'credential',
    );

    expect(result.errorMessage).not.toContain('MCP call failed');
    expect(result.errorMessage).not.toContain('blocked_by_outbound_url_policy');
  });

  it('allows ordinary params that do not collide', async () => {
    const adapter = makeAdapter();

    // Expected to pass input validation and then stop at the SSRF check.
    // What matters is only that it is NOT rejected as a reserved-name
    // collision.
    const result = await adapter.invoke(
      tool,
      action,
      'host-42',
      { reason: 'containment', durationMinutes: 30 },
      'credential',
    );

    expect(result.success).toBe(false);
    expect(result.errorMessage).not.toContain('reserved argument name');
  });

  it('ignores a non-object params value rather than rejecting it', async () => {
    const adapter = makeAdapter();

    for (const params of [null, undefined, 'a string', 42, ['resource']]) {
      const result = await adapter.invoke(
        tool,
        action,
        'host-42',
        params,
        'credential',
      );
      expect(result.errorMessage).not.toContain('reserved argument name');
    }
  });

  it('does not treat an inherited prototype property as a collision', async () => {
    const adapter = makeAdapter();

    // A spread copies own enumerable keys only, so an inherited `resource`
    // could never have reached the MCP server. Rejecting it would fail
    // requests that were never dangerous.
    const params = Object.create({ resource: 'host-999' }) as Record<
      string,
      unknown
    >;
    params.reason = 'containment';

    const result = await adapter.invoke(
      tool,
      action,
      'host-42',
      params,
      'credential',
    );

    expect(result.errorMessage).not.toContain('reserved argument name');
  });
});
