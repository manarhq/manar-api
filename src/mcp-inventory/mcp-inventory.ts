import { z } from 'zod';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { mcpFlags, type McpFlag } from './mcp-risk';

/** Same 30 minutes as the AI tools page (`MONITORING_STALE_MS`, not imported to avoid a cycle). */
const STALE_MS = 30 * 60 * 1000;

/** One server in `POST /host/v1/inventory` (`mcpServers`). The device masks; we also cap sizes. */
export const McpServerReportSchema = z.object({
  tool: z.string().regex(/^host\.[a-z0-9-]{1,40}$/),
  name: z.string().min(1).max(100),
  transport: z.enum(['stdio', 'http', 'sse']),
  /** Base name of the program only. */
  command: z.string().max(100).nullish(),
  argCount: z.number().int().min(0).max(1000).default(0),
  /** Scheme, host and port only. */
  url: z.string().max(200).nullish(),
  package: z.string().max(200).nullish(),
  version: z.string().max(100).nullish(),
  envKeys: z.array(z.string().max(100)).max(40).default([]),
  outsideHome: z.boolean().default(false),
});
export type McpServerReport = z.infer<typeof McpServerReportSchema>;

/**
 * Replaces the stored list of one device with the reported one (a server left out is gone) and
 * returns the servers seen for the first time. Tenant scoping: `client` is the tenant's database
 * and `hostId` comes from the device's verified certificate.
 */
export async function replaceHostMcpServers(
  client: TenantPrismaClient,
  hostId: string,
  servers: readonly McpServerReport[],
  now: Date,
): Promise<{ toolId: string; name: string; flags: McpFlag[] }[]> {
  const existing = await client.hostMcpServer.findMany({
    where: { hostId },
    select: { toolId: true, name: true },
  });
  const had = new Set(existing.map((e) => `${e.toolId}|${e.name}`));
  const seen = new Set<string>();
  const fresh: { toolId: string; name: string; flags: McpFlag[] }[] = [];
  const rows = servers.filter((s) => {
    const k = `${s.tool}|${s.name}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  await client.$transaction([
    client.hostMcpServer.deleteMany({
      where: {
        hostId,
        NOT: rows.map((s) => ({ toolId: s.tool, name: s.name })),
      },
    }),
    ...rows.map((s) => {
      const data = {
        transport: s.transport,
        command: s.command ?? null,
        argCount: s.argCount,
        outsideHome: s.outsideHome,
        url: s.url ?? null,
        pkg: s.package ?? null,
        pkgVersion: s.version ?? null,
        envKeys: s.envKeys,
        lastSeenAt: now,
      };
      return client.hostMcpServer.upsert({
        where: { hostId_toolId_name: { hostId, toolId: s.tool, name: s.name } },
        create: { hostId, toolId: s.tool, name: s.name, ...data },
        update: data,
      });
    }),
  ]);
  for (const s of rows) {
    if (!had.has(`${s.tool}|${s.name}`)) {
      fresh.push({
        toolId: s.tool,
        name: s.name,
        flags: mcpFlags({
          transport: s.transport,
          command: s.command,
          outsideHome: s.outsideHome,
          url: s.url,
          pkg: s.package,
          pkgVersion: s.version,
        }),
      });
    }
  }
  return fresh;
}

/** `GET /mcp-servers`: every server of the workspace's devices, with its flags computed now. */
export async function listMcpServers(client: TenantPrismaClient) {
  const hosts = await client.host.findMany({
    where: { status: { in: ['PENDING', 'APPROVED'] } },
    select: {
      id: true,
      hostname: true,
      lastSeenAt: true,
      mcpServers: { orderBy: [{ toolId: 'asc' }, { name: 'asc' }] },
    },
    orderBy: { createdAt: 'desc' },
    take: 200,
  });
  const now = Date.now();
  const servers = hosts.flatMap((h) =>
    h.mcpServers.map((s) => ({
      id: s.id,
      hostId: h.id,
      hostname: h.hostname,
      toolId: s.toolId,
      name: s.name,
      transport: s.transport,
      command: s.command,
      argCount: s.argCount,
      outsideHome: s.outsideHome,
      url: s.url,
      package: s.pkg,
      version: s.pkgVersion,
      envKeys: s.envKeys,
      firstSeenAt: s.firstSeenAt.toISOString(),
      lastSeenAt: s.lastSeenAt.toISOString(),
      /** The device stopped reporting: the list may be out of date (monitoring unavailable). */
      stale: !h.lastSeenAt || now - h.lastSeenAt.getTime() > STALE_MS,
      flags: mcpFlags({
        transport: s.transport,
        command: s.command,
        outsideHome: s.outsideHome,
        url: s.url,
        pkg: s.pkg,
        pkgVersion: s.pkgVersion,
      }),
    })),
  );
  return { servers };
}
