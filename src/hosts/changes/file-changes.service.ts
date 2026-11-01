import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import { AuditService } from '../../audit/audit.service';
import {
  AUDIT_EVENT_TYPES,
  type AuditActor,
} from '../../audit/audit-event-types';
import type { z } from 'zod';
import type {
  FileChangeBatchSchema,
  RestoreResultSchema,
} from './file-changes.validation';

/** Snapshots live 7 days on the device; the record lives as long. */
export const RETENTION_MS = 7 * 24 * 3600_000;
/** Newest records kept per device. */
export const MAX_PER_HOST = 2000;
const CLOCK_SKEW_MS = 5 * 60_000;

export class FileChangeNotFoundError extends Error {}
export class FileChangeStateError extends Error {}

/**
 * Undo AI file changes. Metadata only (path, size, hash, time): file contents never leave the
 * device. A restore is requested here by an admin and carried out by the device, which reports
 * the result. Every query is scoped to one host in one tenant's database.
 */
@Injectable()
export class FileChangesService {
  constructor(private readonly audit: AuditService) {}

  async report(
    client: TenantPrismaClient,
    hostId: string,
    batch: z.infer<typeof FileChangeBatchSchema>,
    now = new Date(),
  ): Promise<{ accepted: number }> {
    const oldest = now.getTime() - RETENTION_MS;
    const rows = batch.changes
      .map((c) => {
        const t = Date.parse(c.takenAt);
        // A clock that is far off must not make a record immortal or instantly expired.
        const takenAt = new Date(
          t > oldest && t < now.getTime() + CLOCK_SKEW_MS ? t : now.getTime(),
        );
        return {
          hostId,
          snapshotId: c.snapshotId,
          tool: c.tool,
          path: c.path,
          existed: c.existed,
          sizeBytes: c.sizeBytes,
          sha256: c.sha256,
          takenAt,
          expiresAt: new Date(takenAt.getTime() + RETENTION_MS),
        };
      })
      .filter((r) => r.expiresAt > now);
    const { count } = await client.hostFileChange.createMany({
      data: rows,
      skipDuplicates: true,
    });
    await client.hostFileChange.deleteMany({
      where: { hostId, expiresAt: { lt: now } },
    });
    const extra = await client.hostFileChange.findMany({
      where: { hostId },
      orderBy: { takenAt: 'desc' },
      skip: MAX_PER_HOST,
      select: { id: true },
    });
    if (extra.length) {
      await client.hostFileChange.deleteMany({
        where: { id: { in: extra.map((e) => e.id) } },
      });
    }
    return { accepted: count };
  }

  list(client: TenantPrismaClient, hostId: string, now = new Date()) {
    return client.hostFileChange.findMany({
      where: { hostId, expiresAt: { gt: now } },
      orderBy: { takenAt: 'desc' },
      take: 200,
      select: {
        id: true,
        tool: true,
        path: true,
        existed: true,
        sizeBytes: true,
        takenAt: true,
        expiresAt: true,
        restoreStatus: true,
        restoreRequestedAt: true,
        restoreDoneAt: true,
        restoreNote: true,
      },
    });
  }

  async requestRestore(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    hostId: string,
    changeId: string,
    now = new Date(),
  ) {
    const change = await client.hostFileChange.findFirst({
      where: { id: changeId, hostId },
    });
    if (!change || change.expiresAt <= now) throw new FileChangeNotFoundError();
    if (change.restoreStatus === 'REQUESTED')
      throw new FileChangeStateError('A restore is already waiting');
    const { count } = await client.hostFileChange.updateMany({
      where: { id: changeId, hostId, restoreStatus: { not: 'REQUESTED' } },
      data: {
        restoreStatus: 'REQUESTED',
        restoreRequestedBy: actor.id,
        restoreRequestedAt: now,
        restoreDoneAt: null,
        restoreNote: null,
      },
    });
    if (!count) throw new FileChangeStateError('A restore is already waiting');
    await this.audit.record(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.HOST_FILE_CHANGE_RESTORE_REQUESTED,
      actor,
      data: { hostId, changeId, path: change.path },
    });
    return { id: changeId, restoreStatus: 'REQUESTED' as const };
  }

  /** What the device must do now. The path comes from what the device itself reported. */
  pendingRestores(
    client: TenantPrismaClient,
    hostId: string,
    now = new Date(),
  ) {
    return client.hostFileChange.findMany({
      where: { hostId, restoreStatus: 'REQUESTED', expiresAt: { gt: now } },
      orderBy: { restoreRequestedAt: 'asc' },
      take: 20,
      select: {
        id: true,
        snapshotId: true,
        path: true,
        existed: true,
        sha256: true,
      },
    });
  }

  async restoreResult(
    client: TenantPrismaClient,
    tenantId: string,
    hostId: string,
    changeId: string,
    result: z.infer<typeof RestoreResultSchema>,
    now = new Date(),
  ): Promise<void> {
    const { count } = await client.hostFileChange.updateMany({
      where: { id: changeId, hostId, restoreStatus: 'REQUESTED' },
      data: {
        restoreStatus: result.status,
        restoreDoneAt: now,
        restoreNote:
          result.status === 'FAILED'
            ? (result.error ?? 'failed')
            : (result.note ?? null),
      },
    });
    if (!count) throw new FileChangeNotFoundError();
    await this.audit.record(client, tenantId, {
      eventType:
        result.status === 'RESTORED'
          ? AUDIT_EVENT_TYPES.HOST_FILE_CHANGE_RESTORED
          : AUDIT_EVENT_TYPES.HOST_FILE_CHANGE_RESTORE_FAILED,
      actor: { type: 'system', id: `host:${hostId}` },
      data: { hostId, changeId },
    });
  }
}
