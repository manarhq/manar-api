import { PrismaPg } from '@prisma/adapter-pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { PrismaClient } from '../generated/tenant-client/client';
import {
  parseMcpServers,
  replaceHostMcpServers,
} from '../mcp-inventory/mcp-inventory';
import { SessionsService } from './sessions.service';

/**
 * Against a real, migrated tenant database. Skipped unless INSIGHT_DB_URL is set:
 *   INSIGHT_DB_URL=postgresql://... vitest run src/sessions/sessions.db.spec.ts
 */
const url = process.env.INSIGHT_DB_URL;
describe.skipIf(!url)('insight on PostgreSQL', () => {
  let db: PrismaClient;
  const T0 = Date.now() - 3 * 3600_000;
  let seq = 0;

  const ev = (
    host: string,
    min: number,
    type: string,
    data: Record<string, unknown>,
  ) =>
    db.$executeRaw`INSERT INTO audit_events (id, "eventType", "correlationId", actor, "timestamp", data, "eventHash", "partitionSeq")
      VALUES (${`e${seq}`}, ${type}, 'c', '{}'::jsonb, ${new Date(T0 + min * 60_000)}, ${JSON.stringify({ hostId: host, toolId: 'host.cursor', ...data })}::jsonb, 'h', ${seq++})`;

  beforeAll(async () => {
    db = new PrismaClient({ adapter: new PrismaPg({ connectionString: url }) });
    await db.hostGroup.create({
      data: { id: 'g', name: 'g', updatedAt: new Date() },
    });
    for (const id of ['hA', 'hB'])
      await db.host.create({
        data: {
          id,
          hostGroupId: 'g',
          machineId: id,
          hostname: `pc-${id}`,
          os: 'linux',
          keyType: 'SOFTWARE',
          registeredFromIp: '1.1.1.1',
          keyFingerprint: id,
          updatedAt: new Date(),
        } as never,
      });
  });
  afterAll(async () => {
    await db.$executeRaw`DELETE FROM audit_events`;
    await db.host.deleteMany();
    await db.hostGroup.deleteMany();
    await db.$disconnect();
  });

  it('keeps same-name servers apart, drops a bad entry, and removes what the device stops reporting', async () => {
    const base = { tool: 'host.cursor', name: 'db', transport: 'stdio' };
    const list = parseMcpServers([
      { ...base, command: 'npx', package: 'a', version: '1.0.0' },
      { ...base, command: 'bash' },
      { ...base, name: 'long', command: 'npx', package: 'x'.repeat(300) },
      { ...base, name: 'edge', command: 'npx', package: 'y'.repeat(214) },
      { ...base, name: 'bad name\n$(x)' },
      'junk',
      null,
    ]);
    expect(list.map((s) => s.name)).toEqual(['db', 'db', 'edge']);
    const fresh = await replaceHostMcpServers(db, 'hA', list, new Date());
    expect(fresh).toHaveLength(3);
    expect(await db.hostMcpServer.count({ where: { hostId: 'hA' } })).toBe(3);
    await replaceHostMcpServers(db, 'hA', list.slice(0, 1), new Date());
    expect(await db.hostMcpServer.count({ where: { hostId: 'hA' } })).toBe(1);
    expect(await db.hostMcpServer.count({ where: { hostId: 'hB' } })).toBe(0);
  });

  it('lists sessions per device, with approvals, and a noisy device cannot push another out', async () => {
    // hA: noisy, one hook session of 1600 actions; hB: one quiet session with an approval.
    await db.$executeRaw`INSERT INTO audit_events (id, "eventType", "correlationId", actor, "timestamp", data, "eventHash", "partitionSeq")
      SELECT 'bulk' || g, 'host.action_decided', 'c', '{}'::jsonb, ${new Date(T0 + 60_000)}::timestamp + g * interval '1 second',
        '{"hostId":"hA","toolId":"host.cursor","actionId":"read","resource":"/a","decision":"ALLOW","sessionId":"S","caller":"uid:1000"}'::jsonb, 'h', 100000 + g
      FROM generate_series(1, 1600) g`;
    await ev('hB', 0, 'host.action_decided', {
      actionId: 'shell',
      resource: 'git push --force',
      decision: 'APPROVAL_REQUIRED',
      approvalId: 'ap1',
      caller: 'uid:1000',
    });
    await db.$executeRaw`INSERT INTO audit_events (id, "eventType", "correlationId", actor, "timestamp", data, "eventHash", "partitionSeq")
      VALUES ('apx', 'approval.denied', 'c', '{}'::jsonb, ${new Date(T0 + 60_000)}, '{"approvalRequestId":"ap1"}'::jsonb, 'h', ${seq++})`;
    const svc = new SessionsService(
      { getClient: vi.fn(() => Promise.resolve(db)) } as never,
      { recordSafely: vi.fn() } as never,
      {} as never,
    );
    const { sessions } = await svc.list('t', 14);
    const b = sessions.find((s) => s.hostId === 'hB')!;
    expect(b.counts).toMatchObject({ commands: 1, approvals: 1 });
    expect(b.hostname).toBe('pc-hB');
    const a = sessions.find((s) => s.hostId === 'hA')!;
    expect(a.counts.files).toBe(1500); // newest 1500 per device
    expect(a.stepCount).toBe(1000); // steps shown are capped
    const detail = await svc.get('t', b.id);
    expect(detail.steps.map((x) => x.kind)).toEqual(['command', 'approval']);
    // another account on the same device and tool is its own session
    await ev('hB', 5, 'host.action_decided', {
      actionId: 'read',
      resource: '/x',
      decision: 'ALLOW',
      caller: 'uid:1001',
    });
    const again = (await svc.list('t', 14)).sessions.filter(
      (s) => s.hostId === 'hB',
    );
    expect(again).toHaveLength(2);
  });
});
