import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { computeContentHash } from '../policy/policy-content-codec';
import {
  DEFAULT_START_MODE,
  START_MODE_POLICY_NAME,
  START_MODE_PRESETS,
  modeForContentHash,
  type StartMode,
} from './start-mode.presets';

export interface StartModeState {
  mode: StartMode | 'custom';
  versionId: string;
  version: number;
}

/**
 * The active start mode is the latest PUBLISHED version of the `start-mode` policy. A switch
 * creates and publishes the next version, and writes its audit events, in one serializable
 * transaction: the engine sees the old preset or the new one, never a mix or a gap.
 */
@Injectable()
export class StartModeService {
  constructor(private readonly auditService: AuditService) {}

  async current(client: TenantPrismaClient): Promise<StartModeState | null> {
    const policy = await client.policy.findUnique({
      where: { name: START_MODE_POLICY_NAME },
    });
    if (!policy) return null;
    const v = await client.policyVersion.findFirst({
      where: { policyId: policy.id, status: 'PUBLISHED' },
      orderBy: { version: 'desc' },
    });
    if (!v) return null;
    return {
      mode: modeForContentHash(v.contentHash),
      versionId: v.id,
      version: v.version,
    };
  }

  /** Reads the mode; a workspace that never chose one is seeded with the default (Ask me). */
  async currentOrSeed(
    client: TenantPrismaClient,
    tenantId: string,
    userId: string,
  ): Promise<StartModeState> {
    return (
      (await this.current(client)) ??
      (await this.set(client, tenantId, userId, DEFAULT_START_MODE))
    );
  }

  async set(
    client: TenantPrismaClient,
    tenantId: string,
    userId: string,
    mode: StartMode,
  ): Promise<StartModeState> {
    const content = START_MODE_PRESETS[mode];
    const contentHash = computeContentHash(content);
    const publish: Array<() => void> = [];
    const result = await client.$transaction(
      async (tx) => {
        const policy = await tx.policy.upsert({
          where: { name: START_MODE_POLICY_NAME },
          create: {
            name: START_MODE_POLICY_NAME,
            description: 'The start mode chosen for this workspace.',
          },
          update: {},
        });
        const latest = await tx.policyVersion.findFirst({
          where: { policyId: policy.id },
          orderBy: { version: 'desc' },
        });
        const published = await tx.policyVersion.findFirst({
          where: { policyId: policy.id, status: 'PUBLISHED' },
          orderBy: { version: 'desc' },
        });
        const from = published
          ? modeForContentHash(published.contentHash)
          : null;
        if (published && from === mode) {
          return { mode, versionId: published.id, version: published.version };
        }
        const now = new Date();
        const row = await tx.policyVersion.create({
          data: {
            policyId: policy.id,
            version: (latest?.version ?? 0) + 1,
            status: 'PUBLISHED',
            publishedAt: now,
            content,
            contentHash,
            authorId: userId,
            reason: `Start mode: ${mode}`,
            previousVersionId: latest?.id ?? null,
          },
        });
        publish.push(
          await this.auditService.recordManyInTransaction(tx, tenantId, [
            {
              eventType: AUDIT_EVENT_TYPES.POLICY_PUBLISHED,
              actor: { type: 'human', id: userId },
              data: {
                policyId: policy.id,
                versionId: row.id,
                version: row.version,
                contentHash,
                publishedAt: now,
              },
            },
            {
              eventType: AUDIT_EVENT_TYPES.START_MODE_CHANGED,
              actor: { type: 'human', id: userId },
              data: { from, to: mode, versionId: row.id, version: row.version },
            },
          ]),
        );
        return { mode, versionId: row.id, version: row.version };
      },
      { isolationLevel: 'Serializable' },
    );
    publish.forEach((fn) => fn());
    return result;
  }
}
