import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import { rolesOf, splitRoles } from '../../auth/membership.service';
import { isRoleName, ROLES, type RoleName } from '../../auth/roles';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { KeycloakAdminClient } from '../../keycloak/keycloak-admin.client';

/**
 * `pnpm manar memberships:migrate-from-realms`
 *
 * One-off, idempotent, run on every upgrade (the Helm migration job runs it after
 * `tenants:migrate`): for every ACTIVE tenant that has its own Keycloak realm, read the roles users
 * hold in that realm NOW from the Keycloak admin API and write them as `Membership` rows (issuer =
 * the realm). A user with several roles gets all of them. An existing Membership is never
 * overwritten, so later edits in Manar stick. Not a snapshot of the last sign-in: a role removed in
 * Keycloak yesterday is not migrated. Hosted workspaces have no realm and are skipped. If Keycloak
 * cannot be read the tenant fails (exit 1); there is no fallback to old data.
 */
@Command({
  name: 'memberships:migrate-from-realms',
  description:
    "Turn each tenant realm's current role assignments into Membership rows",
})
export class MembershipsMigrateCommand extends CommandRunner {
  private readonly logger = new Logger(MembershipsMigrateCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly keycloak: KeycloakAdminClient,
  ) {
    super();
  }

  async run(): Promise<void> {
    const tenants = await this.control.tenant.findMany({
      where: {
        status: 'ACTIVE',
        keycloakRealm: { not: null },
        keycloakIssuerUrl: { not: null },
      },
    });
    let created = 0;
    let skipped = 0;
    let failed = 0;
    for (const tenant of tenants) {
      try {
        const rolesBySubject = new Map<string, RoleName[]>();
        for (const role of ROLES) {
          for (const subject of await this.keycloak.listRealmRoleMemberIds(
            tenant.keycloakRealm!,
            role,
          )) {
            rolesBySubject.set(subject, [
              ...(rolesBySubject.get(subject) ?? []),
              role,
            ]);
          }
        }
        const issuer = tenant.keycloakIssuerUrl!.replace(/\/+$/, '');
        for (const [subject, roles] of rolesBySubject) {
          const split = splitRoles(roles);
          if (!split) continue;
          const exists = await this.control.membership.findUnique({
            where: {
              issuer_subject_tenantId: { issuer, subject, tenantId: tenant.id },
            },
          });
          if (exists) {
            skipped++;
            continue;
          }
          await this.control.membership.create({
            data: {
              issuer,
              subject,
              tenantId: tenant.id,
              ...split,
              status: 'ACTIVE',
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
  issuer?: string;
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
    const issuer = (o.issuer ?? tenant.keycloakIssuerUrl ?? '').replace(
      /\/+$/,
      '',
    );
    if (!issuer) {
      this.logger.error(
        '--issuer is required: this tenant has no realm of its own',
      );
      process.exitCode = 1;
      return;
    }
    await this.control.membership.upsert({
      where: {
        issuer_subject_tenantId: {
          issuer,
          subject: o.subject,
          tenantId: tenant.id,
        },
      },
      create: {
        issuer,
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
    flags: '-i, --issuer <url>',
    description: "Issuer of the subject (default: the tenant's own realm)",
  })
  parseIssuer(v: string): string {
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
