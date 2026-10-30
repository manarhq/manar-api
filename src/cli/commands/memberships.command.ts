import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { rolesOf, splitRoles } from '../../auth/membership.service';
import { isRoleName, ROLES, type RoleName } from '../../auth/roles';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';

/**
 * `pnpm manar memberships:migrate-from-realms`
 *
 * One-off, idempotent, run on upgrade (hosted staging, pilot installs): for every ACTIVE tenant,
 * turn the roles Manar mirrored from the tenant's Keycloak realm (`RoleBinding` rows, synced from
 * the token at each sign-in until this release) into `Membership` rows. A user with several roles
 * gets all of them. An existing Membership is never overwritten. Users who never signed in have no
 * mirror row and must be granted a role again (`memberships:grant`).
 */
@Command({
  name: 'memberships:migrate-from-realms',
  description: "Turn each tenant's mirrored realm roles into Membership rows",
})
export class MembershipsMigrateCommand extends CommandRunner {
  private readonly logger = new Logger(MembershipsMigrateCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
  ) {
    super();
  }

  async run(): Promise<void> {
    const tenants = await this.control.tenant.findMany({
      where: {
        status: 'ACTIVE',
        databaseBinding: { provisioningStatus: 'ACTIVE' },
      },
    });
    let created = 0;
    let skipped = 0;
    let failed = 0;
    for (const tenant of tenants) {
      try {
        const client = await this.tenants.getClient(tenant.id);
        const users = await client.userProfile.findMany({
          include: { roleBindings: true },
        });
        for (const user of users) {
          const split = splitRoles(
            user.roleBindings
              .map((b) => b.role)
              .filter((r): r is RoleName => isRoleName(r)),
          );
          if (!split) continue;
          const exists = await this.control.membership.findUnique({
            where: {
              subject_tenantId: {
                subject: user.keycloakSubject,
                tenantId: tenant.id,
              },
            },
          });
          if (exists) {
            skipped++;
            continue;
          }
          await this.control.membership.create({
            data: {
              subject: user.keycloakSubject,
              tenantId: tenant.id,
              ...split,
              status: 'ACTIVE',
              email: user.email || null,
              displayName: user.displayName,
              grantedBy: 'system:migrate-from-realms',
            },
          });
          created++;
        }
      } catch (error) {
        failed++;
        this.logger.error(
          `Tenant "${tenant.slug}" failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    this.logger.log(
      `Memberships created=${created} skipped(existing)=${skipped} tenantsFailed=${failed}`,
    );
    process.exitCode = failed > 0 ? 1 : 0;
  }
}

interface GrantOptions {
  tenant: string;
  subject: string;
  roles: RoleName[];
}

/**
 * `pnpm manar memberships:grant --tenant <slug> --subject <keycloak sub> --roles TENANT_OWNER,...`
 * Bootstraps the first owner of a customer-hosted install (there is no other way in: the guard
 * refuses a user with no Membership).
 */
@Command({
  name: 'memberships:grant',
  description:
    'Give a Keycloak subject roles in a workspace (creates or updates the Membership)',
})
export class MembershipsGrantCommand extends CommandRunner {
  private readonly logger = new Logger(MembershipsGrantCommand.name);

  constructor(private readonly control: ControlPrismaService) {
    super();
  }

  async run(_p: string[], o: GrantOptions): Promise<void> {
    const tenant = await this.control.tenant.findUnique({
      where: { slug: o.tenant },
    });
    if (!tenant) {
      this.logger.error(`No tenant with slug "${o.tenant}"`);
      process.exitCode = 1;
      return;
    }
    const split = splitRoles(o.roles);
    if (!split) {
      this.logger.error('--roles needs at least one role');
      process.exitCode = 1;
      return;
    }
    await this.control.membership.upsert({
      where: { subject_tenantId: { subject: o.subject, tenantId: tenant.id } },
      create: {
        subject: o.subject,
        tenantId: tenant.id,
        ...split,
        status: 'ACTIVE',
        grantedBy: 'system:cli',
      },
      update: { ...split, status: 'ACTIVE', grantedBy: 'system:cli' },
    });
    this.logger.log(
      `Granted ${rolesOf({ ...split }).join(', ')} in "${tenant.slug}"`,
    );
  }

  @Option({
    flags: '-t, --tenant <slug>',
    description: 'Tenant slug',
    required: true,
  })
  parseTenant(v: string): string {
    return v;
  }

  @Option({
    flags: '-s, --subject <sub>',
    description: 'Keycloak subject (sub claim)',
    required: true,
  })
  parseSubject(v: string): string {
    return v;
  }

  @Option({
    flags: '-r, --roles <roles>',
    description: `Comma-separated: ${ROLES.join(', ')}`,
    required: true,
  })
  parseRoles(v: string): RoleName[] {
    const roles = v.split(',').map((r) => r.trim());
    const bad = roles.filter((r) => !isRoleName(r));
    if (bad.length) throw new Error(`Unknown role(s): ${bad.join(', ')}`);
    return roles as RoleName[];
  }
}
