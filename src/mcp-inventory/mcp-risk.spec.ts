import { describe, expect, it } from 'vitest';
import { mcpFlags } from './mcp-risk';

describe('mcpFlags', () => {
  it('flags nothing for a pinned package from a known publisher', () => {
    expect(
      mcpFlags({
        transport: 'stdio',
        command: 'npx',
        pkg: '@modelcontextprotocol/server-memory',
        pkgVersion: '1.2.3',
      }),
    ).toEqual([]);
  });

  it.each([undefined, '', 'latest', '^1.2.0', '~1', '>=1', '1.x', '*'])(
    'treats %j as unpinned',
    (v) => {
      expect(
        mcpFlags({
          transport: 'stdio',
          command: 'npx',
          pkg: '@stripe/mcp',
          pkgVersion: v,
        }),
      ).toEqual(['unpinned_version']);
    },
  );

  it('accepts exact versions and container digests as pinned', () => {
    for (const v of ['1.0.0', 'v2.3', '0.6.2-beta.1', 'sha256:abc123']) {
      expect(
        mcpFlags({
          transport: 'stdio',
          command: 'docker',
          pkg: 'mcp/fetch',
          pkgVersion: v,
        }),
      ).toEqual([]);
    }
  });

  it('flags an unknown publisher and a local script', () => {
    expect(
      mcpFlags({
        transport: 'stdio',
        command: 'npx',
        pkg: 'random-mcp',
        pkgVersion: '1.0.0',
      }),
    ).toEqual(['unknown_publisher']);
    expect(mcpFlags({ transport: 'stdio', command: 'server' })).toEqual([
      'unknown_publisher',
    ]);
  });

  it('flags remote http without TLS, but not loopback or https', () => {
    expect(
      mcpFlags({ transport: 'http', url: 'http://mcp.notion.com/mcp' }),
    ).toEqual(['remote_no_tls']);
    expect(
      mcpFlags({ transport: 'http', url: 'http://10.0.0.5:8080/mcp' }),
    ).toEqual(['unknown_publisher', 'remote_no_tls']);
    expect(
      mcpFlags({ transport: 'http', url: 'http://localhost:3000/mcp' }),
    ).toEqual(['unknown_publisher']);
    expect(
      mcpFlags({ transport: 'http', url: 'https://mcp.notion.com/mcp' }),
    ).toEqual([]);
  });

  it('flags servers that run a shell', () => {
    for (const command of ['bash', 'sh', 'cmd', 'powershell', 'pwsh']) {
      expect(mcpFlags({ transport: 'stdio', command })).toContain('runs_shell');
    }
    expect(mcpFlags({ transport: 'stdio', command: 'node' })).not.toContain(
      'runs_shell',
    );
  });

  it('flags writes outside the home folder from the device-side hint', () => {
    const base = {
      transport: 'stdio',
      command: 'npx',
      pkg: '@modelcontextprotocol/server-filesystem',
      pkgVersion: '1.0.0',
    };
    expect(mcpFlags({ ...base, outsideHome: true })).toEqual([
      'writes_outside_home',
    ]);
    expect(mcpFlags({ ...base, outsideHome: false })).toEqual([]);
  });

  it('judges an entry with both a command and a url on both', () => {
    // A known remote host cannot vouch for a local shell.
    expect(
      mcpFlags({
        transport: 'http',
        command: 'bash',
        url: 'https://mcp.notion.com/mcp',
      }),
    ).toEqual(['unknown_publisher', 'runs_shell']);
    // Nor can a known package vouch for an unknown or unencrypted remote.
    expect(
      mcpFlags({
        transport: 'http',
        command: 'npx',
        pkg: '@stripe/mcp',
        pkgVersion: '1.0.0',
        url: 'http://evil.example/mcp',
      }),
    ).toEqual(['unknown_publisher', 'remote_no_tls']);
    expect(
      mcpFlags({
        transport: 'stdio',
        command: 'node',
        outsideHome: true,
        url: 'https://mcp.notion.com/mcp',
      }),
    ).toContain('writes_outside_home');
  });
});
