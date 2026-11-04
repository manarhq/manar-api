import {
  Body,
  ConflictException,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  Logger,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Put,
  Query,
  UseGuards,
  type OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import type { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { KeycloakAdminClient } from '../../keycloak/keycloak-admin.client';
import { ChangeRequestsService } from '../approvals/change-requests.service';
import { StaffAuditService } from '../audit/staff-audit.service';
import { newInviteToken } from '../auth/staff-invites';
import { StaffAuthGuard } from '../auth/staff-auth.guard';
import {
  RequirePermission,
  StaffPermissionGuard,
  StaffSignedIn,
} from '../auth/staff-permission.guard';
import { CurrentStaff, type StaffPrincipal } from '../auth/staff-principal';
import { StepUp } from '../auth/step-up';
import { BUILT_IN_ROLE_KEYS } from '../rbac/permissions';
import { MAX_ELEVATION_MS, StaffRbacService } from '../rbac/staff-rbac.service';
import { StaffAlertsService } from '../staff-alerts.service';
import { parse } from './parse';

const TEAMS = [
  'DEV',
  'SALES',
  'PARTNERSHIPS',
  'SUPPORT',
  'BILLING',
  'TRUST_SAFETY',
  'LEADERSHIP',
] as const;
const Invite = z.object({
  email: z.email().transform((e) => e.toLowerCase()),
  displayName: z.string().trim().min(2).max(120),
  team: z.enum(TEAMS),
  title: z.string().trim().max(60).default(''),
  entraOid: z.uuid().optional(),
});
const Profile = z.object({
  displayName: z.string().trim().min(2).max(120).optional(),
  team: z.enum(TEAMS).optional(),
  title: z.string().trim().max(60).optional(),
});
const RoleBody = z.object({
  key: z.string(),
  name: z.string().trim().min(2).max(60),
  description: z.string().max(500).optional(),
  permissions: z.array(z.string()).max(60),
});
const GroupBody = z.object({
  name: z.string().trim().min(2).max(60),
  description: z.string().max(500).default(''),
});
const MemberBody = z.object({ staffId: z.uuid() });
const AssignBody = z.object({
  roleId: z.uuid(),
  principalType: z.enum(['STAFF', 'GROUP']),
  principalId: z.uuid(),
  kind: z.enum(['ACTIVE', 'ELIGIBLE']).default('ACTIVE'),
  expiresAt: z.coerce.date().optional(),
  reason: z.string().trim().min(10).max(500),
});
const ElevateBody = z.object({
  roleKey: z.string().default('owner'),
  reason: z.string().trim().min(10).max(500),
});
const Grant = z.object({
  roleId: z.uuid(),
  principalType: z.enum(['STAFF', 'GROUP']),
  principalId: z.uuid(),
  kind: z.enum(['ACTIVE', 'ELIGIBLE']),
  expiresAt: z.coerce.date().optional(),
});

/**
 * Staff administration and JIT elevation (DESK spec §10.3, §11.1, §11.3, §16). Owner grants (the
 * Owner role, or eligibility for it) and every custom-role grant are two-person change requests;
 * built-in non-Owner roles are granted directly by `staff.manage`. Elevation is self-service with
 * a reason and a passkey and tells the other Owners at once (AC-32).
 */
@Controller('staff/v1')
@UseGuards(StaffAuthGuard, StaffPermissionGuard)
export class StaffAdminController implements OnModuleInit {
  private readonly logger = new Logger(StaffAdminController.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly rbac: StaffRbacService,
    private readonly changes: ChangeRequestsService,
    private readonly audit: StaffAuditService,
    private readonly alerts: StaffAlertsService,
    private readonly keycloak: KeycloakAdminClient,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  onModuleInit() {
    const grantExecutor = (
      perm: 'staff.owner.grant.approve' | 'staff.manage',
    ) => ({
      approvePermissions: () => [perm],
      // Nobody approves a grant to themselves.
      refuseDecider: async (cr: { payload: unknown }, d: StaffPrincipal) => {
        const g = Grant.parse(cr.payload);
        if (g.principalType === 'STAFF' && g.principalId === d.staffId)
          return 'own_grant';
        if (
          g.principalType === 'GROUP' &&
          (await this.control.staffGroupMember.findUnique({
            where: {
              groupId_staffId: { groupId: g.principalId, staffId: d.staffId },
            },
          }))
        )
          return 'own_grant';
        return null;
      },
      execute: async (cr: {
        id: string;
        proposedBy: string;
        payload: unknown;
      }) => {
        const g = Grant.parse(cr.payload);
        const a = await this.rbac.grant({
          ...g,
          grantedBy: cr.proposedBy,
          changeRequestId: cr.id,
        });
        return { assignmentId: a.id };
      },
    });
    this.changes.register(
      'owner_grant',
      grantExecutor('staff.owner.grant.approve'),
    );
    this.changes.register('role_grant', grantExecutor('staff.manage'));
  }

  @Get('staff')
  @RequirePermission('staff.view')
  async members() {
    const [members, assignments, groups] = await Promise.all([
      this.control.staffMember.findMany({ orderBy: { createdAt: 'asc' } }),
      this.control.staffRoleAssignment.findMany({
        where: { revokedAt: null },
        include: { role: { select: { key: true, name: true, builtIn: true } } },
      }),
      this.control.staffGroupMember.findMany({
        include: { group: { select: { id: true, name: true } } },
      }),
    ]);
    const now = new Date();
    const elevations = await this.control.staffElevation.findMany({
      where: { endedAt: null, expiresAt: { gt: now } },
    });
    return members.map((m) => ({
      id: m.id,
      email: m.email,
      displayName: m.displayName,
      title: m.title,
      team: m.team,
      status: m.status,
      boundAt: m.boundAt,
      roles: assignments
        .filter((a) => a.principalType === 'STAFF' && a.principalId === m.id)
        .map((a) => ({
          assignmentId: a.id,
          roleId: a.roleId,
          key: a.role.key,
          name: a.role.name,
          builtIn: a.role.builtIn,
          kind: a.kind,
          expiresAt: a.expiresAt,
        })),
      groups: groups.filter((g) => g.staffId === m.id).map((g) => g.group),
      elevation: elevations.find((e) => e.staffId === m.id) ?? null,
    }));
  }

  @Post('staff')
  @RequirePermission('staff.manage')
  async invite(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    const i = parse(Invite, body);
    const token = i.entraOid ? null : newInviteToken();
    const row = await this.control.$transaction(async (tx) => {
      const created = await tx.staffMember
        .create({
          data: {
            email: i.email,
            displayName: i.displayName,
            team: i.team,
            title: i.title,
            ...(token
              ? {
                  inviteTokenHash: token.hash,
                  inviteExpiresAt: token.expiresAt,
                }
              : { entraOid: i.entraOid, status: 'ACTIVE' as const }),
          },
        })
        .catch((e: { code?: string }) => {
          if (e.code === 'P2002')
            throw new ConflictException({
              code: 'staff_exists',
              message: 'A staff member with this email or Entra id exists.',
            });
          throw e;
        });
      await this.audit.append(
        {
          staffId: s.staffId,
          action: 'staff.invited',
          targetType: 'STAFF',
          targetId: created.id,
          data: { team: i.team, byEntraOid: !!i.entraOid },
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
      return created;
    });
    // The token is shown once to the inviter, who hands it over out of band (Desk /invite#token).
    return {
      id: row.id,
      inviteToken: token?.token ?? null,
      inviteExpiresAt: token?.expiresAt ?? null,
    };
  }

  @Patch('staff/:id')
  @RequirePermission('staff.manage')
  async update(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    const p = parse(Profile, body);
    const row = await this.control.staffMember
      .update({ where: { id }, data: p })
      .catch(() => {
        throw new NotFoundException();
      });
    await this.audit.append({
      staffId: s.staffId,
      action: 'staff.updated',
      targetType: 'STAFF',
      targetId: id,
      data: p,
      ip: s.ip,
      requestId: s.requestId,
    });
    return row;
  }

  @Post('staff/:id/disable')
  @HttpCode(200)
  @RequirePermission('staff.manage')
  @StepUp()
  async disable(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    if (id === s.staffId)
      throw new ForbiddenException({
        code: 'self',
        message: 'You cannot disable yourself.',
      });
    const target = await this.control.staffMember.findUnique({ where: { id } });
    if (!target) throw new NotFoundException();
    if (
      (await this.isOwner(id)) &&
      !(await this.rbac.can(s.staffId, 'staff.owner.grant.approve'))
    )
      throw new ForbiddenException({
        code: 'owner_only',
        message: 'Only an Owner can disable an Owner.',
      });
    await this.control.$transaction(async (tx) => {
      await tx.staffMember.update({
        where: { id },
        data: { status: 'DISABLED' },
      });
      await this.audit.append(
        {
          staffId: s.staffId,
          action: 'staff.disabled',
          targetType: 'STAFF',
          targetId: id,
          ip: s.ip,
          requestId: s.requestId,
        },
        tx,
      );
    });
    // The guard refuses DISABLED at once; ending the Keycloak sessions is the second wall.
    const realm = this.config
      .get('STAFF_OIDC_ISSUER', { infer: true })
      ?.split('/realms/')[1];
    let sessionsEnded = false;
    if (realm && target.subject)
      sessionsEnded = await this.keycloak
        .logoutUser(realm, target.subject)
        .then(
          () => true,
          (e: unknown) => (
            this.logger.warn(`staff sessions not ended: ${String(e)}`),
            false
          ),
        );
    return { ok: true, sessionsEnded };
  }

  /** Owner directly, or through a group (groups cannot be granted Owner; counted anyway). */
  private async isOwner(staffId: string) {
    const role = await this.control.staffRole.findUnique({
      where: { key: 'owner' },
    });
    const groups = await this.control.staffGroupMember.findMany({
      where: { staffId },
      select: { groupId: true },
    });
    return !!(await this.control.staffRoleAssignment.findFirst({
      where: {
        roleId: role?.id,
        revokedAt: null,
        OR: [
          { principalType: 'STAFF', principalId: staffId },
          {
            principalType: 'GROUP',
            principalId: { in: groups.map((g) => g.groupId) },
          },
        ],
      },
    }));
  }

  private async groupHoldsOwner(groupId: string) {
    const role = await this.control.staffRole.findUnique({
      where: { key: 'owner' },
    });
    return !!(await this.control.staffRoleAssignment.findFirst({
      where: {
        roleId: role?.id,
        principalType: 'GROUP',
        principalId: groupId,
        revokedAt: null,
      },
    }));
  }

  @Get('staff-roles')
  @RequirePermission('staff.view')
  async roles() {
    const roles = await this.control.staffRole.findMany({
      where: { archivedAt: null },
      include: { versions: { orderBy: { version: 'desc' } } },
      orderBy: { createdAt: 'asc' },
    });
    const counts = await this.control.staffRoleAssignment.groupBy({
      by: ['roleId'],
      where: { revokedAt: null },
      _count: { _all: true },
    });
    return roles.map((r) => ({
      id: r.id,
      key: r.key,
      name: r.name,
      description: r.description,
      builtIn: r.builtIn,
      version: r.currentVersion,
      permissions:
        r.versions.find((v) => v.version === r.currentVersion)?.permissions ??
        [],
      versions: r.versions.map((v) => ({
        version: v.version,
        createdBy: v.createdBy,
        createdAt: v.createdAt,
        permissions: v.permissions,
      })),
      holders: counts.find((c) => c.roleId === r.id)?._count._all ?? 0,
    }));
  }

  @Post('staff-roles')
  @RequirePermission('staff.roles.manage')
  createRole(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    const b = parse(RoleBody, body);
    return this.rbac.saveCustomRole({ ...b, by: s.staffId });
  }

  @Put('staff-roles/:id')
  @RequirePermission('staff.roles.manage')
  editRole(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    const b = parse(RoleBody, body);
    return this.rbac.saveCustomRole({ ...b, roleId: id, by: s.staffId });
  }

  @Get('staff-groups')
  @RequirePermission('staff.view')
  groups() {
    return this.control.staffGroup.findMany({
      include: { members: true },
      orderBy: { createdAt: 'asc' },
    });
  }

  @Post('staff-groups')
  @RequirePermission('staff.manage')
  async createGroup(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    const b = parse(GroupBody, body);
    const g = await this.control.staffGroup.create({
      data: { ...b, createdBy: s.staffId },
    });
    await this.audit.append({
      staffId: s.staffId,
      action: 'staff.group_created',
      targetType: 'GROUP',
      targetId: g.id,
      data: { name: g.name },
      ip: s.ip,
      requestId: s.requestId,
    });
    return g;
  }

  @Post('staff-groups/:id/members')
  @RequirePermission('staff.manage')
  async addMember(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: unknown,
  ) {
    await this.rbac.addGroupMember(
      id,
      parse(MemberBody, body).staffId,
      s.staffId,
    );
    return { ok: true };
  }

  @Delete('staff-groups/:id/members/:staffId')
  @RequirePermission('staff.manage')
  async removeMember(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
    @Param('staffId', ParseUUIDPipe) staffId: string,
  ) {
    // Same rule as removing Owner access directly (defensive: groups cannot hold Owner).
    if (
      (await this.groupHoldsOwner(id)) &&
      !(await this.rbac.can(s.staffId, 'staff.owner.grant.approve'))
    )
      throw new ForbiddenException({
        code: 'owner_only',
        message: 'Only an Owner can change Owner access.',
      });
    await this.rbac.removeGroupMember(id, staffId, s.staffId);
    return { ok: true };
  }

  /** Owner grants and custom roles need a second person; built-in non-Owner roles are direct. */
  @Post('staff-assignments')
  @RequirePermission('staff.manage')
  async assign(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    const a = parse(AssignBody, body);
    const role = await this.control.staffRole.findUnique({
      where: { id: a.roleId },
    });
    if (!role || role.archivedAt)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such role.',
      });
    const payload = {
      roleId: a.roleId,
      principalType: a.principalType,
      principalId: a.principalId,
      kind: a.kind,
      expiresAt: a.expiresAt?.toISOString(),
    };
    if (role.key === 'owner') {
      if (
        !(await this.rbac
          .can(s.staffId, 'staff.owner.grant.propose')
          .catch((e: unknown) => throwFailClosed('openfga', e)))
      )
        throw new ForbiddenException({
          code: 'permission_required',
          message: "Your role doesn't allow proposing an Owner grant.",
        });
      return {
        changeRequest: await this.changes.propose(s, {
          kind: 'owner_grant',
          targetId: `${a.principalId}:${a.roleId}`,
          payload,
          reason: a.reason,
        }),
      };
    }
    if (!role.builtIn)
      return {
        changeRequest: await this.changes.propose(s, {
          kind: 'role_grant',
          targetId: `${a.principalId}:${a.roleId}`,
          payload,
          reason: a.reason,
        }),
      };
    if (!(BUILT_IN_ROLE_KEYS as readonly string[]).includes(role.key))
      throw new NotFoundException();
    const assignment = await this.rbac.grant({ ...a, grantedBy: s.staffId });
    return { assignment };
  }

  @Delete('staff-assignments/:id')
  @RequirePermission('staff.manage')
  async revoke(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    const a = await this.control.staffRoleAssignment.findUnique({
      where: { id },
      include: { role: true },
    });
    if (!a || a.revokedAt) throw new NotFoundException();
    if (
      a.role.key === 'owner' &&
      !(await this.rbac.can(s.staffId, 'staff.owner.grant.approve'))
    )
      throw new ForbiddenException({
        code: 'owner_only',
        message: 'Only an Owner can remove Owner access.',
      });
    await this.rbac.revoke(id, s.staffId);
    return { ok: true };
  }

  @Get('audit')
  @RequirePermission('staff.audit.view')
  async auditLog(
    @Query('before') before?: string,
    @Query('staffId') staffId?: string,
    @Query('targetId') targetId?: string,
  ) {
    const rows = await this.audit.list({
      before: before && /^\d+$/.test(before) ? BigInt(before) : undefined,
      staffId,
      targetId,
      limit: 100,
    });
    return rows.map((r) => ({ ...r, seq: r.seq.toString() }));
  }

  @Post('audit/verify')
  @HttpCode(200)
  @RequirePermission('staff.audit.view')
  verify() {
    return this.audit.verify();
  }

  @Get('elevations')
  @RequirePermission('staff.view')
  elevations() {
    return this.control.staffElevation.findMany({
      orderBy: { startedAt: 'desc' },
      take: 100,
    });
  }

  /** JIT elevation (spec §11.1): own ELIGIBLE assignment, reason, passkey, one hour, Owners told. */
  @Post('elevations')
  @StaffSignedIn()
  @StepUp()
  async elevate(@CurrentStaff() s: StaffPrincipal, @Body() body: unknown) {
    const b = parse(ElevateBody, body);
    const role = await this.control.staffRole.findUnique({
      where: { key: b.roleKey },
    });
    const eligible = role
      ? await this.control.staffRoleAssignment.findFirst({
          where: {
            roleId: role.id,
            principalType: 'STAFF',
            principalId: s.staffId,
            kind: 'ELIGIBLE',
            revokedAt: null,
          },
        })
      : null;
    if (!eligible)
      throw new ForbiddenException({
        code: 'not_eligible',
        message: 'You are not eligible for this role.',
      });
    const e = await this.rbac.startElevation({
      staffId: s.staffId,
      assignmentId: eligible.id,
      reason: b.reason,
      expiresAt: new Date(Date.now() + MAX_ELEVATION_MS),
    });
    await this.audit.checkpoint().catch(() => undefined);
    await this.alerts
      .alertOwners(
        'elevation_started',
        {
          who: s.displayName,
          role: role!.name,
          reason: b.reason,
          until: e.expiresAt.toISOString(),
        },
        s.staffId,
      )
      .catch((err: unknown) =>
        this.logger.warn(`elevation alert failed: ${String(err)}`),
      );
    return e;
  }

  @Post('elevations/:id/end')
  @HttpCode(200)
  @StaffSignedIn()
  async endElevation(
    @CurrentStaff() s: StaffPrincipal,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    const e = await this.control.staffElevation.findUnique({ where: { id } });
    if (!e || e.staffId !== s.staffId)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No active elevation of yours.',
      });
    await this.rbac.endElevation(id, s.staffId);
    return { ok: true };
  }
}
