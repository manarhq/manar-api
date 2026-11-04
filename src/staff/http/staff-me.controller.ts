import { Controller, Get, UseGuards } from '@nestjs/common';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { StaffAuthGuard } from '../auth/staff-auth.guard';
import {
  StaffPermissionGuard,
  StaffSignedIn,
} from '../auth/staff-permission.guard';
import {
  CurrentStaff,
  badge,
  type StaffPrincipal,
} from '../auth/staff-principal';
import { StaffRbacService } from '../rbac/staff-rbac.service';
import { NoStaffAudit } from './staff-audit.interceptor';

/** The caller's own staff profile, roles, elevation and reveals (spec §16). */
@Controller('staff/v1/me')
@UseGuards(StaffAuthGuard, StaffPermissionGuard)
@StaffSignedIn()
@NoStaffAudit()
export class StaffMeController {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly rbac: StaffRbacService,
  ) {}

  @Get()
  async me(@CurrentStaff() staff: StaffPrincipal) {
    const now = new Date();
    const groups = await this.control.staffGroupMember.findMany({
      where: { staffId: staff.staffId },
      select: { groupId: true },
    });
    const [assignments, elevation, reveals] = await Promise.all([
      this.control.staffRoleAssignment.findMany({
        where: {
          revokedAt: null,
          OR: [
            { principalType: 'STAFF', principalId: staff.staffId },
            {
              principalType: 'GROUP',
              principalId: { in: groups.map((g) => g.groupId) },
            },
          ],
          AND: [{ OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] }],
        },
        include: { role: { select: { key: true, name: true } } },
        orderBy: { createdAt: 'asc' },
      }),
      this.control.staffElevation.findFirst({
        where: {
          staffId: staff.staffId,
          endedAt: null,
          expiresAt: { gt: now },
        },
      }),
      this.control.staffReveal.findMany({
        where: { staffId: staff.staffId, expiresAt: { gt: now } },
        select: { targetType: true, targetId: true, expiresAt: true },
      }),
    ]);
    const elevatedRole = elevation
      ? assignments.find((a) => a.id === elevation.assignmentId)?.role
      : undefined;
    return {
      staff: {
        id: staff.staffId,
        email: staff.email,
        displayName: staff.displayName,
        title: staff.title,
        team: staff.team,
        badge: badge(staff),
      },
      roles: assignments.map((a) => ({
        assignmentId: a.id,
        roleId: a.roleId,
        key: a.role.key,
        name: a.role.name,
        kind: a.kind,
        via: a.principalType === 'GROUP' ? 'group' : 'direct',
        expiresAt: a.expiresAt,
      })),
      elevation: elevation
        ? {
            id: elevation.id,
            roleKey: elevatedRole?.key,
            roleName: elevatedRole?.name,
            startedAt: elevation.startedAt,
            expiresAt: elevation.expiresAt,
          }
        : null,
      reveals,
      stepUp: { acr: staff.acr ?? null, authTime: staff.authTime ?? null },
    };
  }

  @Get('permissions')
  async permissions(@CurrentStaff() staff: StaffPrincipal) {
    try {
      return { permissions: await this.rbac.permissionsOf(staff.staffId) };
    } catch (error) {
      throwFailClosed('openfga', error);
    }
  }
}
