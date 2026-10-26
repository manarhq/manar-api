import { describe, expect, it } from 'vitest';
import { CloudMcpConfigSchema, cloudMcpConfigIssues } from './cloud-mcp.config';

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
});
