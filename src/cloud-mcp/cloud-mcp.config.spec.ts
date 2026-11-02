import { describe, expect, it } from 'vitest';
import {
  CloudMcpConfigSchema,
  cloudMcpClientId,
  cloudMcpConfigIssues,
  cloudMcpScope,
  cloudMcpSettings,
} from './cloud-mcp.config';

describe('CloudMcpConfigSchema', () => {
  it('is off with nothing set and with the chart defaults', () => {
    expect(cloudMcpConfigIssues(CloudMcpConfigSchema.parse({}))).toEqual([]);
    const chart = CloudMcpConfigSchema.parse({
      MANAR_MCP_ENABLED: 'false',
      MANAR_MCP_HOST: '',
    });
    expect(chart.MANAR_MCP_HOST).toBeUndefined();
  });

  it('needs a bare host when enabled', () => {
    expect(
      cloudMcpConfigIssues(
        CloudMcpConfigSchema.parse({ MANAR_MCP_ENABLED: 'true' }),
      ),
    ).toEqual(['MANAR_MCP_HOST: required when MANAR_MCP_ENABLED is true']);
    expect(
      CloudMcpConfigSchema.safeParse({
        MANAR_MCP_HOST: 'https://mcp.example.com/x',
      }).success,
    ).toBe(false);
  });

  it('takes plain host names only for DCR trusted hosts', () => {
    const ok = (v: string) =>
      CloudMcpConfigSchema.safeParse({ MANAR_MCP_DCR_TRUSTED_HOSTS: v })
        .success;
    expect(ok('chatgpt.com')).toBe(true);
    expect(ok('chatgpt.com, openai.com')).toBe(true);
    expect(ok('*.chatgpt.com')).toBe(false);
    expect(ok('https://chatgpt.com')).toBe(false);
    expect(ok('chatgpt.com:443')).toBe(false);
    expect(ok('localhost')).toBe(false);
  });

  it('takes plain host names only for legacy hosts', () => {
    const ok = (v: string) =>
      CloudMcpConfigSchema.safeParse({ MANAR_MCP_LEGACY_HOSTS: v }).success;
    expect(ok('mcp-manar.vax.sh')).toBe(true);
    expect(ok('')).toBe(true);
    expect(ok('https://mcp-manar.vax.sh')).toBe(false);
    expect(ok('mcp-manar.vax.sh:443')).toBe(false);
  });

  it('names tenant-prefixed scope and client on the shared realm only', () => {
    expect(cloudMcpScope('a')).toBe('manar-mcp-a');
    expect(cloudMcpScope('a', 't1')).toBe('manar-mcp-t1-a');
    expect(cloudMcpClientId('a')).toBe('manar-cloud-a');
    expect(cloudMcpClientId('a', 't1')).toBe('manar-cloud-t1-a');
    expect(
      CloudMcpConfigSchema.parse({ MANAR_MCP_SHARED_ISSUER: '' })
        .MANAR_MCP_SHARED_ISSUER,
    ).toBeUndefined();
  });
});

describe('ChatGPT on the shared realm', () => {
  it('is on unless MANAR_MCP_CHATGPT_ENABLED is false', () => {
    const on = (v?: string) =>
      cloudMcpSettings({
        get: (k: string) => (k === 'MANAR_MCP_CHATGPT_ENABLED' ? v : undefined),
      } as never).chatGptOnSharedRealm;
    expect(on(undefined)).toBe(true);
    expect(on('true')).toBe(true);
    expect(on('false')).toBe(false);
  });
});
