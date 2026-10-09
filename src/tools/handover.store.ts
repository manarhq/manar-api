import {
  Injectable,
  Logger,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import { OpenBaoKvClient } from '../openbao/openbao-kv.client';

/** KV v1 mount (`deploy/openbao-init.mjs`): no versions, so a delete cannot be undone. */
export const HANDOVER_MOUNT = 'handover';
/** An uncollected handover is deleted after this. */
export const HANDOVER_TTL_MS = 24 * 60 * 60 * 1000;
const SWEEP_EVERY_MS = 10 * 60 * 1000;

/**
 * ADR-0011: a value an executed action produced for the approving person
 * only (a temporary password). It lives only in OpenBao KV v1 under the
 * tenant and approval request, never in PostgreSQL, logs or audit; there
 * is no fallback store. `take` hands it out once and deletes it; anything
 * older than `HANDOVER_TTL_MS` is never handed out and is deleted by the
 * sweep (every 10 minutes in each API process, and on `take`).
 */
@Injectable()
export class HandoverStore implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(HandoverStore.name);
  private timer?: NodeJS.Timeout;

  constructor(private readonly kv: OpenBaoKvClient) {}

  onModuleInit(): void {
    this.timer = setInterval(() => {
      this.sweep().catch((error: unknown) =>
        this.logger.warn(
          `Handover sweep failed: ${error instanceof Error ? error.name : 'unknown'}`,
        ),
      );
    }, SWEEP_EVERY_MS);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    clearInterval(this.timer);
  }

  async put(
    tenantId: string,
    approvalRequestId: string,
    value: Record<string, string>,
  ): Promise<void> {
    await this.kv.writeV1(path(tenantId, approvalRequestId), {
      value: JSON.stringify(value),
      createdAt: Date.now(),
    });
  }

  /** The value, once; `null` when there is none (never stored, collected, or expired). Throws when OpenBao fails. */
  async take(
    tenantId: string,
    approvalRequestId: string,
  ): Promise<Record<string, string> | null> {
    const at = path(tenantId, approvalRequestId);
    const stored = await this.kv.readV1(at);
    if (!stored) return null;
    // ponytail: read then delete is not atomic (KV v1 has no check-and-set),
    // so two concurrent collects by the same approver could both read it.
    // A KV v2 CAS write would close that but keeps soft-deleted versions.
    await this.kv.deleteV1(at);
    if (this.expired(stored) || typeof stored.value !== 'string') return null;
    return JSON.parse(stored.value) as Record<string, string>;
  }

  /** Deletes every handover older than `HANDOVER_TTL_MS`, in every tenant. Returns how many. */
  async sweep(): Promise<number> {
    let deleted = 0;
    for (const tenant of await this.kv.listV1(HANDOVER_MOUNT)) {
      for (const key of await this.kv.listV1(`${HANDOVER_MOUNT}/${tenant}`)) {
        // A listed folder key ends in "/".
        const at = `${HANDOVER_MOUNT}/${tenant}${key}`;
        const stored = await this.kv.readV1(at);
        if (stored && this.expired(stored)) {
          await this.kv.deleteV1(at);
          deleted += 1;
        }
      }
    }
    return deleted;
  }

  private expired(stored: Record<string, unknown>): boolean {
    const created = Number(stored.createdAt);
    return !Number.isFinite(created) || Date.now() - created > HANDOVER_TTL_MS;
  }
}

function path(tenantId: string, approvalRequestId: string): string {
  return `${HANDOVER_MOUNT}/${encodeURIComponent(tenantId)}/${encodeURIComponent(approvalRequestId)}`;
}
