import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type { StaffTeam } from '../../generated/control-client/client';
import { StaffAuditService } from '../../staff/audit/staff-audit.service';
import { newInviteToken } from '../../staff/auth/staff-invites';
import { StaffRbacService } from '../../staff/rbac/staff-rbac.service';
import {
  isBuiltInRole,
  isStaffTeam,
  type SeedOptions,
} from './staff-seed.options';

/**
 * `pnpm manar staff:seed --email <e> --name <n> --role owner|admin|... [--eligible owner] --team <t> [--title <t>] [--entra-oid <oid>]`
 *
 * Idempotent by email: creates an INVITED staff row (bound to an Entra identity at first sign-in,
 * AC-43) and its role assignments, and makes sure the built-in roles exist. Re-running it adds a
 * missing assignment and changes nothing else.
 */
@Command({
  name: 'staff:seed',
  description: 'Create or complete a staff member and their roles',
})
export class StaffSeedCommand extends CommandRunner {
  private readonly logger = new Logger(StaffSeedCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly rbac: StaffRbacService,
    private readonly audit: StaffAuditService,
  ) {
    super();
  }

  async run(_p: string[], o: SeedOptions): Promise<void> {
    if (!o.email || !o.name || !o.role || !o.team)
      throw new Error('--email, --name, --role and --team are required');
    if (!isBuiltInRole(o.role) || (o.eligible && !isBuiltInRole(o.eligible)))
      throw new Error('--role and --eligible take a built-in role key');
    if (!isStaffTeam(o.team))
      throw new Error(
        '--team: DEV, SALES, PARTNERSHIPS, SUPPORT, BILLING, TRUST_SAFETY or LEADERSHIP',
      );
    await this.rbac.ensureBuiltInRoles();
    const email = o.email.trim().toLowerCase();
    let member = await this.control.staffMember.findUnique({
      where: { email },
    });
    if (!member) {
      // Bound by an immutable id only (security review, 4 Nov): the Entra object id when the
      // operator has it (Entra admin centre, Users, Object ID), else a one-time invite token.
      const invite = o.entraOid ? null : newInviteToken();
      member = await this.control.staffMember.create({
        data: {
          email,
          displayName: o.name,
          title: o.title ?? '',
          team: o.team as StaffTeam,
          ...(invite
            ? {
                inviteTokenHash: invite.hash,
                inviteExpiresAt: invite.expiresAt,
              }
            : { entraOid: o.entraOid, status: 'ACTIVE' as const }),
        },
      });
      if (invite) {
        // Never printed: written for the operator to hand over out of band (the person opens
        // Desk at /invite#<token>), mode 600 like the Keycloak setup credentials.
        const dir = join(homedir(), '.manar-staff', 'invites');
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const file = join(dir, `${email}.txt`);
        writeFileSync(file, `${invite.token}\n`, { mode: 0o600 });
        this.logger.log(
          `invite token for ${email} written to ${file} (valid 7 days)`,
        );
      }
      await this.audit.append({
        staffId: null,
        action: 'staff.seeded',
        targetType: 'STAFF',
        targetId: member.id,
        data: { team: o.team },
      });
    }
    const assign = async (key: string, kind: 'ACTIVE' | 'ELIGIBLE') => {
      const role = await this.control.staffRole.findUniqueOrThrow({
        where: { key },
      });
      const has = await this.control.staffRoleAssignment.findFirst({
        where: {
          roleId: role.id,
          principalType: 'STAFF',
          principalId: member.id,
          kind,
          revokedAt: null,
        },
      });
      if (!has)
        await this.rbac.grant({
          roleId: role.id,
          principalType: 'STAFF',
          principalId: member.id,
          kind,
          grantedBy: 'system',
        });
    };
    await assign(o.role, 'ACTIVE');
    if (o.eligible) await assign(o.eligible, 'ELIGIBLE');
    this.logger.log(`staff ${member.id} ready (${member.status})`);
  }

  @Option({ flags: '--email <email>' }) parseEmail(v: string) {
    return v;
  }
  @Option({ flags: '--name <name>' }) parseName(v: string) {
    return v;
  }
  @Option({ flags: '--role <role>' }) parseRole(v: string) {
    return v;
  }
  @Option({ flags: '--eligible <role>' }) parseEligible(v: string) {
    return v;
  }
  @Option({ flags: '--team <team>' }) parseTeam(v: string) {
    return v.toUpperCase();
  }
  @Option({ flags: '--entra-oid <oid>' }) parseEntraOid(v: string) {
    if (!/^[0-9a-f-]{36}$/i.test(v))
      throw new Error('--entra-oid takes an Entra object id (a GUID)');
    return v.toLowerCase();
  }
  @Option({ flags: '--title <title>' }) parseTitle(v: string) {
    return v;
  }
}

@Command({
  name: 'rbac:reconcile',
  description: 'Repair OpenFGA staff tuples towards Postgres',
})
export class RbacReconcileCommand extends CommandRunner {
  private readonly logger = new Logger(RbacReconcileCommand.name);
  constructor(private readonly rbac: StaffRbacService) {
    super();
  }
  async run(
    _p: string[],
    o: { dryRun?: boolean; allowMassDelete?: boolean },
  ): Promise<void> {
    const r = await this.rbac.reconcile({
      dryRun: !!o.dryRun,
      allowMassDelete: !!o.allowMassDelete,
    });
    if (r.blocked)
      throw new Error(
        `would delete ${r.wouldDelete} tuples; check the plan with --dry-run, then pass --allow-mass-delete`,
      );
    this.logger.log(
      `${o.dryRun ? 'would fix' : 'fixed'} ${r.fixed} tuple(s), ${r.wouldDelete} deletion(s)`,
    );
  }
  @Option({ flags: '--dry-run' }) parseDry() {
    return true;
  }
  @Option({ flags: '--allow-mass-delete' }) parseMassDelete() {
    return true;
  }
}
