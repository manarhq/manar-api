/**
 * Deterministic risk flags for one MCP server (insight track). A pure function of what the device
 * reported: no network, no model, no clock. A flag only ever ADDS a warning; a server with no flags
 * is "nothing found", never "safe". Plain-words explanations live in the console messages.
 */
export const MCP_FLAGS = [
  'unknown_publisher',
  'unpinned_version',
  'remote_no_tls',
  'runs_shell',
  'writes_outside_home',
] as const;
export type McpFlag = (typeof MCP_FLAGS)[number];

export interface McpServerFacts {
  transport: string;
  command?: string | null;
  /** Worked out on the device from the arguments, which are not sent. */
  outsideHome?: boolean;
  url?: string | null;
  pkg?: string | null;
  pkgVersion?: string | null;
}

/** npm scopes and names of publishers we recognise (vendors of the tools and of the protocol). */
const KNOWN_NPM_SCOPES = [
  '@modelcontextprotocol',
  '@anthropic-ai',
  '@openai',
  '@google',
  '@googlemaps',
  '@github',
  '@microsoft',
  '@azure',
  '@cloudflare',
  '@stripe',
  '@notionhq',
  '@supabase',
  '@sentry',
  '@linear',
  '@atlassian',
  '@playwright',
  '@upstash',
  '@vercel',
  '@aws',
  '@datadog',
  '@figma',
  '@slack',
];
const KNOWN_PACKAGES = new Set([
  'mcp-server-git',
  'mcp-server-fetch',
  'mcp-server-time',
  'mcp-server-sqlite',
  'context7-mcp',
  'chrome-devtools-mcp',
  'firecrawl-mcp',
]);
/** Container registries and namespaces of known publishers. */
const KNOWN_IMAGE_PREFIXES = [
  'mcp/', // Docker's own MCP catalogue
  'docker.io/mcp/',
  'ghcr.io/github/',
  'ghcr.io/modelcontextprotocol/',
  'mcr.microsoft.com/',
];
/** Hosts of remote servers run by their vendors. */
const KNOWN_REMOTE_HOSTS = [
  'api.githubcopilot.com',
  'mcp.notion.com',
  'mcp.stripe.com',
  'mcp.linear.app',
  'mcp.sentry.dev',
  'mcp.atlassian.com',
  'mcp.cloudflare.com',
  'mcp.supabase.com',
  'mcp.figma.com',
  'mcp.context7.com',
  'learn.microsoft.com',
  'mcp.deepwiki.com',
];

const SHELLS = new Set([
  'sh',
  'bash',
  'zsh',
  'fish',
  'dash',
  'ksh',
  'csh',
  'tcsh',
  'cmd',
  'powershell',
  'pwsh',
  'wsl',
]);
function baseName(p: string): string {
  const parts = p.replace(/\\/g, '/').split('/');
  return (parts[parts.length - 1] ?? '')
    .toLowerCase()
    .replace(/\.(exe|cmd|bat)$/, '');
}

function loopback(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  return (
    h === 'localhost' ||
    h.endsWith('.localhost') ||
    h === '::1' ||
    /^127\.\d+\.\d+\.\d+$/.test(h)
  );
}

function hostOf(url: string): { scheme: string; host: string } | null {
  try {
    const u = new URL(url);
    return {
      scheme: u.protocol.replace(':', '').toLowerCase(),
      host: u.hostname,
    };
  } catch {
    return null;
  }
}

function knownPublisher(s: McpServerFacts): boolean {
  if (s.url) {
    const h = hostOf(s.url)?.host.toLowerCase();
    return !!h && KNOWN_REMOTE_HOSTS.includes(h);
  }
  const pkg = (s.pkg ?? '').toLowerCase();
  if (!pkg) return false; // a local script or binary: we cannot tell who made it
  if (KNOWN_PACKAGES.has(pkg)) return true;
  if (KNOWN_NPM_SCOPES.some((sc) => pkg.startsWith(`${sc}/`))) return true;
  return KNOWN_IMAGE_PREFIXES.some((p) => pkg.startsWith(p));
}

/** A version is pinned when it is one exact version, or a container digest. */
function pinned(version: string | null | undefined): boolean {
  const v = (version ?? '').trim().toLowerCase();
  if (!v || v === 'latest' || v === 'next' || v === 'stable' || v === '*')
    return false;
  if (v.startsWith('sha256:')) return true;
  return /^v?\d+(\.\d+){0,3}([-+][0-9a-z.-]+)?$/.test(v);
}

export function mcpFlags(s: McpServerFacts): McpFlag[] {
  const flags: McpFlag[] = [];
  if (!knownPublisher(s)) flags.push('unknown_publisher');
  // Unpinned: a launcher that fetches a package or image without one exact version. Remote servers
  // have no version to pin, so they get no such flag.
  if (!s.url && s.pkg && !pinned(s.pkgVersion)) flags.push('unpinned_version');
  if (s.url) {
    const u = hostOf(s.url);
    if (u && u.scheme === 'http' && !loopback(u.host))
      flags.push('remote_no_tls');
  }
  if (!s.url) {
    // Only the program's base name is reported: a shell as the program is the signal. A shell
    // started by another program (`npx x -c ...`) cannot be seen without the arguments.
    if (SHELLS.has(baseName(s.command ?? ''))) flags.push('runs_shell');
    if (s.outsideHome) flags.push('writes_outside_home');
  }
  return flags;
}
