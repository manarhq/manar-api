import { Injectable, Logger } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { MailerService } from '../growth/mailer.service';
import { StaffAuditService } from './audit/staff-audit.service';
import type { StaffAlerts } from './rbac/staff-rbac.service';

const SUBJECTS: Record<string, string> = {
  elevation_started: 'Manar Desk: a staff member elevated to Owner',
  rbac_reconcile_blocked: 'Manar Desk: RBAC repair stopped, needs a person',
};

/**
 * Tells the Owners (spec §11.4, the rules Phase 1 ships: elevation started, reconcile blocked).
 * Email through the platform mailer; every alert is also a staff audit row, so it is never lost
 * when mail is not configured. Alerts inform; they never block an action.
 */
@Injectable()
export class StaffAlertsService implements StaffAlerts {
  private readonly logger = new Logger(StaffAlertsService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly mailer: MailerService,
    private readonly audit: StaffAuditService,
  ) {}

  async alertOwners(
    kind: string,
    data: Record<string, unknown>,
    exceptStaffId?: string,
  ): Promise<void> {
    const owners = await this.control.staffMember.findMany({
      where: {
        status: 'ACTIVE',
        id: exceptStaffId ? { not: exceptStaffId } : undefined,
      },
      select: { id: true, email: true },
    });
    const ownerRole = await this.control.staffRole.findUnique({
      where: { key: 'owner' },
    });
    const holders = new Set(
      (
        await this.control.staffRoleAssignment.findMany({
          where: {
            roleId: ownerRole?.id,
            kind: 'ACTIVE',
            revokedAt: null,
            principalType: 'STAFF',
          },
          select: { principalId: true },
        })
      ).map((a) => a.principalId),
    );
    const to = owners.filter((o) => holders.has(o.id));
    await this.audit.append({
      staffId: null,
      action: `alert.${kind}`,
      data: { ...data, to: to.map((o) => o.id) },
    });
    const lines = Object.entries(data).map(([k, v]) => `${k}: ${String(v)}`);
    for (const o of to)
      await this.mailer
        .send({
          to: o.email,
          subject: SUBJECTS[kind] ?? `Manar Desk alert: ${kind}`,
          text: lines.join('\n'),
          html: `<p>${lines.map((l) => l.replace(/[<>&]/g, '')).join('<br>')}</p>`,
        })
        .catch((e: unknown) =>
          this.logger.warn(`alert mail to ${o.id} failed: ${String(e)}`),
        );
  }
}
