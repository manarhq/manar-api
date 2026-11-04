import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type { StaffTeam } from '../../generated/control-client/client';
import { StaffAuditService } from '../../staff/audit/staff-audit.service';
import { StaffRbacService } from '../../staff/rbac/staff-rbac.service';
import {
  isBuiltInRole,
  isStaffTeam,
  type SeedOptions,
} from './staff-seed.options';

/**
 * `pnpm manar staff:seed --email <e> --name <n> --role owner|admin|... [--eligible owner] --team <t> [--title <t>]`
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
      member = await this.control.staffMember.create({
        data: {
          email,
          displayName: o.name,
          title: o.title ?? '',
          team: o.team as StaffTeam,
        },
      });
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
