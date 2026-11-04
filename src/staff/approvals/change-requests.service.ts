import { randomInt } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type {
  Prisma,
  StaffChangeRequest,
} from '../../generated/control-client/client';
import { StaffAuditService } from '../audit/staff-audit.service';
import type { StaffPrincipal } from '../auth/staff-principal';
import type { StaffPermission } from '../rbac/permissions';
import { StaffRbacService } from '../rbac/staff-rbac.service';

export const CHANGE_REQUEST_TTL_MS = 24 * 3_600_000;

export type ChangeKind =
  | 'suspend_proposal'
  | 'immediate_restriction'
  | 'unban'
  | 'owner_grant'
  | 'role_grant';

/** What a kind needs from its decider, and what approving it does. */
export interface ChangeExecutor {
  /** Every permission the decider must hold at decision time. */
  approvePermissions(payload: Record<string, unknown>): StaffPermission[];
  /** Extra refusal beyond "not the proposer" (un-ban: not the staff member who banned). */
  refuseDecider?(
    cr: StaffChangeRequest,
    decider: StaffPrincipal,
  ): Promise<string | null>;
  execute(
    cr: StaffChangeRequest,
    decider: StaffPrincipal,
  ): Promise<Record<string, unknown>>;
}

const yymm = () => new Date().toISOString().slice(2, 7).replace('-', '');

/**
 * The two-person rule (DESK spec §11.3): a proposer, then a different staff member who holds the
 * approving permission at decision time and passes the passkey re-check (route level). One open
 * request per (kind, target) by a partial unique index; requests expire after 24 hours; approval
 * executes in the same request and records the outcome.
 */
@Injectable()
export class ChangeRequestsService {
  private readonly executors = new Map<ChangeKind, ChangeExecutor>();

  constructor(
    private readonly control: ControlPrismaService,
    private readonly audit: StaffAuditService,
    private readonly rbac: StaffRbacService,
  ) {}

  register(kind: ChangeKind, executor: ChangeExecutor) {
    this.executors.set(kind, executor);
  }

  async propose(
    s: StaffPrincipal,
    i: {
      kind: ChangeKind;
      targetId: string;
      payload: Record<string, unknown>;
      reason: string;
    },
  ): Promise<StaffChangeRequest> {
    if (!this.executors.has(i.kind))
      throw new Error(`no executor for ${i.kind}`);
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        return await this.control.$transaction(async (tx) => {
          const cr = await tx.staffChangeRequest.create({
            data: {
              code: `CR-${yymm()}-${String(randomInt(10_000)).padStart(4, '0')}`,
              kind: i.kind,
              targetId: i.targetId,
              payload: i.payload as Prisma.InputJsonValue,
              reason: i.reason,
              proposedBy: s.staffId,
              expiresAt: new Date(Date.now() + CHANGE_REQUEST_TTL_MS),
            },
          });
          await this.audit.append(
            {
              staffId: s.staffId,
              action: 'change_request.proposed',
              targetType: 'CHANGE_REQUEST',
              targetId: cr.id,
              data: { kind: i.kind, targetId: i.targetId, reason: i.reason },
              ip: s.ip,
              requestId: s.requestId,
            },
            tx,
          );
          return cr;
        });
      } catch (error) {
        const target = (error as { meta?: { target?: unknown } }).meta?.target;
        const onCode = JSON.stringify(target ?? '').includes('code');
        if ((error as { code?: string }).code === 'P2002' && onCode) continue; // code collision: retry
        if ((error as { code?: string }).code === 'P2002')
          throw new ConflictException({
            code: 'change_request_open',
            message: 'A request for this is already waiting for a decision.',
          });
        throw error;
      }
    }
    throw new ConflictException({
      code: 'change_request_code',
      message: 'Try again.',
    });
  }

  async approve(s: StaffPrincipal, id: string): Promise<StaffChangeRequest> {
    const cr = await this.decidable(s, id);
    const executor = this.executors.get(cr.kind as ChangeKind)!;
    const extra = await executor.refuseDecider?.(cr, s);
    if (extra)
      throw new ForbiddenException({
        code: extra,
        message: 'You cannot decide this request.',
      });
    await this.requirePermissions(
      s,
      executor.approvePermissions(cr.payload as Record<string, unknown>),
    );
    // Only one decider wins: PENDING to APPROVED is a conditional update.
    const won = await this.control.staffChangeRequest.updateMany({
      where: { id: cr.id, status: 'PENDING' },
      data: { status: 'APPROVED', decidedBy: s.staffId, decidedAt: new Date() },
    });
    if (won.count !== 1)
      throw new ConflictException({
        code: 'already_decided',
        message: 'Someone decided this request already.',
      });
    let outcome: Record<string, unknown>;
    try {
      outcome = await executor.execute(cr, s);
    } catch (error) {
      await this.finish(s, cr, 'FAILED', {
        error: (error as Error).message?.slice(0, 300) ?? 'failed',
      });
      throw error;
    }
    return this.finish(s, cr, 'EXECUTED', outcome);
  }

  async reject(
    s: StaffPrincipal,
    id: string,
    note: string,
  ): Promise<StaffChangeRequest> {
    const cr = await this.decidable(s, id);
    const executor = this.executors.get(cr.kind as ChangeKind)!;
    await this.requirePermissions(
      s,
      executor.approvePermissions(cr.payload as Record<string, unknown>),
    );
    const done = await this.control.staffChangeRequest.updateMany({
      where: { id: cr.id, status: 'PENDING' },
      data: {
        status: 'REJECTED',
        decidedBy: s.staffId,
        decidedAt: new Date(),
        decisionNote: note.slice(0, 2000),
      },
    });
    if (done.count !== 1)
      throw new ConflictException({
        code: 'already_decided',
        message: 'Someone decided this request already.',
      });
    await this.audit.append({
      staffId: s.staffId,
      action: 'change_request.rejected',
      targetType: 'CHANGE_REQUEST',
      targetId: cr.id,
      data: { kind: cr.kind },
      ip: s.ip,
      requestId: s.requestId,
    });
    return this.control.staffChangeRequest.findUniqueOrThrow({
      where: { id: cr.id },
    });
  }

  async cancel(s: StaffPrincipal, id: string): Promise<void> {
    const done = await this.control.staffChangeRequest.updateMany({
      where: { id, status: 'PENDING', proposedBy: s.staffId },
      data: {
        status: 'CANCELLED',
        decidedBy: s.staffId,
        decidedAt: new Date(),
      },
    });
    if (done.count !== 1)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No open request of yours with this id.',
      });
    await this.audit.append({
      staffId: s.staffId,
      action: 'change_request.cancelled',
      targetType: 'CHANGE_REQUEST',
      targetId: id,
      ip: s.ip,
      requestId: s.requestId,
    });
  }

  list(s: StaffPrincipal, box: 'waiting' | 'mine' | 'done') {
    const now = new Date();
    return this.control.staffChangeRequest.findMany({
      where:
        box === 'waiting'
          ? {
              status: 'PENDING',
              expiresAt: { gt: now },
              proposedBy: { not: s.staffId },
            }
          : box === 'mine'
            ? {
                status: 'PENDING',
                expiresAt: { gt: now },
                proposedBy: s.staffId,
              }
            : {
                OR: [
                  { status: { notIn: ['PENDING'] } },
                  { expiresAt: { lte: now } },
                ],
              },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
  }

  /** Marks requests past their 24 hours as EXPIRED (they could not be approved anyway). */
  async expireOld(): Promise<number> {
    const r = await this.control.staffChangeRequest.updateMany({
      where: { status: 'PENDING', expiresAt: { lte: new Date() } },
      data: { status: 'EXPIRED' },
    });
    return r.count;
  }

  private async decidable(
    s: StaffPrincipal,
    id: string,
  ): Promise<StaffChangeRequest> {
    const cr = await this.control.staffChangeRequest.findUnique({
      where: { id },
    });
    if (!cr || !this.executors.has(cr.kind as ChangeKind))
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such request.',
      });
    if (cr.status !== 'PENDING')
      throw new ConflictException({
        code: 'already_decided',
        message: 'This request was decided already.',
      });
    if (cr.expiresAt <= new Date()) {
      await this.control.staffChangeRequest.updateMany({
        where: { id, status: 'PENDING' },
        data: { status: 'EXPIRED' },
      });
      throw new ConflictException({
        code: 'expired',
        message:
          'This request expired. Propose it again if it is still needed.',
      });
    }
    if (cr.proposedBy === s.staffId)
      throw new ForbiddenException({
        code: 'own_request',
        message: 'Someone else must decide a request you proposed.',
      });
    return cr;
  }

  private async requirePermissions(
    s: StaffPrincipal,
    perms: StaffPermission[],
  ) {
    let ok: boolean[];
    try {
      ok = await Promise.all(perms.map((p) => this.rbac.can(s.staffId, p)));
    } catch (error) {
      throwFailClosed('openfga', error);
    }
    const missing = perms.filter((_, i) => !ok[i]);
    if (missing.length)
      throw new ForbiddenException({
        code: 'permission_required',
        permissions: missing,
        message: "Your role doesn't allow deciding this.",
      });
  }

  private async finish(
    s: StaffPrincipal,
    cr: StaffChangeRequest,
    status: 'EXECUTED' | 'FAILED',
    outcome: Record<string, unknown>,
  ) {
    const row = await this.control.$transaction(async (tx) => {
      const updated = await tx.staffChangeRequest.update({
        where: { id: cr.id },
        data: { status, outcome: outcome as Prisma.InputJsonValue },
      });
      await this.audit.append(
        {
          staffId: s.staffId,
          action: `change_request.${status.toLowerCase()}`,
          targetType: 'CHANGE_REQUEST',
          targetId: cr.id,
          data: { kind: cr.kind, targetId: cr.targetId, outcome },
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
      return updated;
    });
    // High-risk: sign the audit chain head now, not at the next minute.
    await this.audit.checkpoint().catch(() => undefined);
    return row;
  }
}
