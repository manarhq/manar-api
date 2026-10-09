import { Injectable } from '@nestjs/common';
import { OpenBaoKvClient } from '../openbao/openbao-kv.client';

/** OpenBao soft-deletes an uncollected handover after this. */
const HANDOVER_TTL = '24h';

/**
 * ADR-0011: a value an executed action produced for the approving person
 * only (a temporary password). Kept in OpenBao KV under the tenant and
 * approval request, never in PostgreSQL, logs or audit, and handed out once:
 * `take` destroys it before returning it.
 */
@Injectable()
export class HandoverStore {
  constructor(private readonly kv: OpenBaoKvClient) {}

  async put(
    tenantId: string,
    approvalRequestId: string,
    value: Record<string, string>,
  ): Promise<void> {
    await this.kv.writeSecret(
      path(tenantId, approvalRequestId),
      { value: JSON.stringify(value) },
      { deleteVersionAfter: HANDOVER_TTL },
    );
  }

  /** The value, once; `null` when there is none (never stored, collected, or expired). */
  async take(
    tenantId: string,
    approvalRequestId: string,
  ): Promise<Record<string, string> | null> {
    const at = path(tenantId, approvalRequestId);
    let raw: unknown;
    try {
      raw = (await this.kv.readSecret(at)).value;
    } catch (error) {
      if (
        error instanceof Error &&
        /HTTP 404|has been deleted/.test(error.message)
      ) {
        return null;
      }
      throw error;
    }
    // ponytail: read then destroy is not atomic; two concurrent collects by
    // the same approver could both read it. Use a CAS-guarded write if that matters.
    await this.kv.destroySecret(at);
    return typeof raw === 'string'
      ? (JSON.parse(raw) as Record<string, string>)
      : null;
  }
}

function path(tenantId: string, approvalRequestId: string): string {
  return `handover/${encodeURIComponent(tenantId)}/${encodeURIComponent(approvalRequestId)}`;
}
