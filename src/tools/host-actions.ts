import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';

/**
 * docs/edge.md section 5: local actions of a desktop agent, decided by Manar and executed on the
 * host. The manar-edge Claude Code hook calls `POST /agent/v1/authorize` with `toolId:
 * "host.claude-code"` and `actionId` = Claude Code's tool name lowercased; this catalog gives the
 * common ones their risk metadata so policy, risk and approvals treat them like any other action.
 * A tool name not listed here still authorizes (opaque action id) but adds no risk of its own.
 *
 * The tool row is registered with `enabled: false`: Manar never executes these, so
 * `/agent/v1/tools/invoke` refuses them and the per-task MCP manifest leaves them out, while
 * `/agent/v1/authorize` (which does not read `enabled`) decides them as usual.
 */
export const HOST_CLAUDE_CODE_TOOL = 'host.claude-code';
/** Never callable: `manar:` is not an allowed outbound scheme. */
export const HOST_TOOL_ENDPOINT = 'manar://host';

export interface HostActionDefinition {
  name: string;
  description: string;
  riskBaseScore: number;
  mutating: boolean;
  destructive: boolean;
  /**
   * What `resource` holds, for policy alias matching (src/policy/resource-aliases.ts). Absent
   * means a file path, the fail-closed default: only an action listed here as `command` or
   * `other` is read any other way.
   */
  resourceKind?: 'command' | 'other';
}

/** The catalogue of host tool ids (launch BRIEF section 2; `coverage` extends this list). */
export const KNOWN_HOST_TOOL_IDS: readonly string[] = [
  'host.claude-code',
  'host.claude-desktop',
  'host.cursor',
  'host.windsurf',
  'host.vscode-copilot',
  'host.copilot-cli',
  'host.codex-cli',
  'host.chatgpt-desktop',
  'host.gemini-cli',
];

/**
 * Risk = baseline 10 + base + 15 if mutating + 25 if destructive (src/risk/risk-engine.service.ts).
 * With the default task ceiling of 20: reads and searches run, web fetches run, file changes and
 * shell commands wait for a person's approval.
 */
export const HOST_CLAUDE_CODE_ACTIONS: readonly HostActionDefinition[] = [
  {
    name: 'read',
    description: 'Read a file. Resource: the file path.',
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
  },
  {
    name: 'glob',
    description: 'List files matching a pattern. Resource: the tool name.',
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'grep',
    description: 'Search file contents. Resource: the tool name.',
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'ls',
    description: 'List a directory. Resource: the tool name.',
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'notebookread',
    description: 'Read a notebook. Resource: the file path.',
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
  },
  {
    name: 'todowrite',
    description:
      "Update the session's own task list (no effect outside the session).",
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'task',
    description: 'Start a subagent; its own tool calls are decided one by one.',
    riskBaseScore: 5,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'websearch',
    description: 'Web search through the edge proxy. Resource: the tool name.',
    riskBaseScore: 5,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'webfetch',
    description:
      'Fetch a URL through the edge proxy (allow-listed hosts only). Resource: the URL.',
    riskBaseScore: 10,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'edit',
    description: 'Change part of a file. Resource: the file path.',
    riskBaseScore: 10,
    mutating: true,
    destructive: false,
  },
  {
    name: 'multiedit',
    description: 'Several changes to one file. Resource: the file path.',
    riskBaseScore: 10,
    mutating: true,
    destructive: false,
  },
  {
    name: 'write',
    description: 'Create or overwrite a file. Resource: the file path.',
    riskBaseScore: 10,
    mutating: true,
    destructive: false,
  },
  {
    name: 'notebookedit',
    description: 'Change a notebook cell. Resource: the file path.',
    riskBaseScore: 10,
    mutating: true,
    destructive: false,
  },
  {
    name: 'bash',
    description:
      'Run a shell command as the jailed agent user. Resource: the command (first 2048 characters).',
    riskBaseScore: 20,
    mutating: true,
    destructive: true,
    resourceKind: 'command',
  },
];

/** Registers the host tool and its actions in one tenant. Idempotent; rows are written from this catalog. */
export async function ensureHostClaudeCodeTool(
  tenantClient: TenantPrismaClient,
): Promise<void> {
  const data = {
    type: 'HOST',
    vendor: 'Claude Code',
    description:
      'Local actions of a Claude Code agent on a manar-edge host: decided by Manar, executed on the host, never by Manar.',
    baseEndpoint: HOST_TOOL_ENDPOINT,
    protocol: 'HTTP' as const,
    credentialReference: { provider: 'ENV', reference: 'MANAR_CONNECTOR_NONE' },
    enabled: false,
    metadata: { dataOrigin: 'HOST' },
  };
  const tool = await tenantClient.tool.upsert({
    where: { name: HOST_CLAUDE_CODE_TOOL },
    create: { name: HOST_CLAUDE_CODE_TOOL, ...data },
    update: data,
  });
  for (const action of HOST_CLAUDE_CODE_ACTIONS) {
    const row = {
      description: action.description,
      riskBaseScore: action.riskBaseScore,
      mutating: action.mutating,
      destructive: action.destructive,
      inputSchema: { type: 'object' } as Prisma.InputJsonObject,
    };
    await tenantClient.toolAction.upsert({
      where: { toolId_name: { toolId: tool.id, name: action.name } },
      create: { toolId: tool.id, name: action.name, ...row },
      update: row,
    });
  }
}

/**
 * The other AI tools on a device (public launch spec 4.5 and 6). Their hooks send these generic
 * action ids, mapped from each tool's own event names by manar-edge `internal/protect`:
 * `shell` (resource: the command), `read` / `edit` / `write` (the file path), `mcp` (the
 * `server/tool` name) and `webfetch` (the URL). Risk uses the same formula as Claude Code.
 */
export const HOST_GENERIC_ACTIONS: readonly HostActionDefinition[] = [
  {
    name: 'read',
    description: 'Read a file. Resource: the file path.',
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
  },
  {
    name: 'edit',
    description: 'Change or create a file. Resource: the file path.',
    riskBaseScore: 10,
    mutating: true,
    destructive: false,
  },
  {
    name: 'write',
    description: 'Create or overwrite a file. Resource: the file path.',
    riskBaseScore: 10,
    mutating: true,
    destructive: false,
  },
  {
    name: 'shell',
    description:
      'Run a shell command. Resource: the command (first 2048 characters).',
    riskBaseScore: 20,
    mutating: true,
    destructive: true,
    resourceKind: 'command',
  },
  {
    name: 'mcp',
    description: 'Call an MCP tool. Resource: server/tool.',
    riskBaseScore: 10,
    mutating: true,
    destructive: false,
    resourceKind: 'other',
  },
  {
    name: 'webfetch',
    description: 'Fetch a URL. Resource: the URL.',
    riskBaseScore: 10,
    mutating: false,
    destructive: false,
    resourceKind: 'other',
  },
];

/** How a tool can be protected. A device may never report more than its entry allows. */
export type ProtectMode = 'hook' | 'mcp' | 'gateway' | 'none';

export interface HostToolDefinition {
  id: string;
  name: string;
  /** Modes the tool supports, from the day-1 verification (workspace plan 2026-10-31-coverage). */
  modes: readonly Exclude<ProtectMode, 'none'>[];
}

export const HOST_TOOLS: readonly HostToolDefinition[] = [
  { id: 'host.claude-code', name: 'Claude Code', modes: ['hook', 'gateway'] },
  { id: 'host.cursor', name: 'Cursor', modes: ['hook', 'mcp'] },
  { id: 'host.windsurf', name: 'Windsurf', modes: ['hook', 'mcp'] },
  { id: 'host.gemini-cli', name: 'Gemini CLI', modes: ['hook', 'mcp'] },
  {
    id: 'host.codex-cli',
    name: 'Codex CLI',
    modes: ['hook', 'mcp', 'gateway'],
  },
  { id: 'host.copilot-cli', name: 'Copilot CLI', modes: ['hook', 'mcp'] },
  { id: 'host.vscode-copilot', name: 'VS Code with Copilot', modes: ['mcp'] },
  { id: 'host.claude-desktop', name: 'Claude desktop', modes: ['mcp'] },
  // Remote connectors only: nothing on the device can be wrapped, so it is only seen.
  { id: 'host.chatgpt-desktop', name: 'ChatGPT desktop', modes: [] },
];

export function hostTool(id: string): HostToolDefinition | undefined {
  return HOST_TOOLS.find((t) => t.id === id);
}

/** Registers every non-Claude host tool and the generic actions in one tenant. Idempotent. */
export async function ensureHostTools(
  tenantClient: TenantPrismaClient,
): Promise<void> {
  for (const def of HOST_TOOLS) {
    if (def.id === HOST_CLAUDE_CODE_TOOL) continue;
    const data = {
      type: 'HOST',
      vendor: def.name,
      description: `Local actions of ${def.name} on a manar-edge host: decided by Manar, executed on the host, never by Manar.`,
      baseEndpoint: HOST_TOOL_ENDPOINT,
      protocol: 'HTTP' as const,
      credentialReference: {
        provider: 'ENV',
        reference: 'MANAR_CONNECTOR_NONE',
      },
      enabled: false,
      metadata: { dataOrigin: 'HOST' },
    };
    const tool = await tenantClient.tool.upsert({
      where: { name: def.id },
      create: { name: def.id, ...data },
      update: data,
    });
    for (const action of HOST_GENERIC_ACTIONS) {
      const row = {
        description: action.description,
        riskBaseScore: action.riskBaseScore,
        mutating: action.mutating,
        destructive: action.destructive,
        inputSchema: { type: 'object' } as Prisma.InputJsonObject,
      };
      await tenantClient.toolAction.upsert({
        where: { toolId_name: { toolId: tool.id, name: action.name } },
        create: { toolId: tool.id, name: action.name, ...row },
        update: row,
      });
    }
  }
}

/** Same formula as src/risk/risk-engine.service.ts: 10 + base + 15 mutating + 25 destructive. */
export function hostActionRisk(
  toolId: string,
  actionId: string,
): number | null {
  // Claude Code on an enrolled device (manar-edge hook-tool) sends the generic ids (shell, mcp,
  // ...) like every other tool; agent mode (install-claude-code) sends its own tool names.
  const a =
    (toolId === HOST_CLAUDE_CODE_TOOL
      ? HOST_CLAUDE_CODE_ACTIONS.find((x) => x.name === actionId)
      : undefined) ?? HOST_GENERIC_ACTIONS.find((x) => x.name === actionId);
  if (!a) return null;
  return (
    10 + a.riskBaseScore + (a.mutating ? 15 : 0) + (a.destructive ? 25 : 0)
  );
}
