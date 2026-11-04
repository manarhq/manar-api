import { Logger } from '@nestjs/common';
import { Command, CommandRunner } from 'nest-commander';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { DeviceIndexService } from '../../staff/index/device-index.service';
import { normalizeEmail } from '../../staff/restrictions/fingerprints';

/**
 * `pnpm manar accounts:backfill`: one `accounts` row for every person with a membership (shared
 * and legacy realms), named and addressed from the membership and the verified contact email.
 * Idempotent; existing rows only gain missing fields. People who signed in but never created a
 * workspace appear at their next sign-in.
 */
@Command({
  name: 'accounts:backfill',
  description: 'Fill the staff account index from memberships',
})
export class AccountsBackfillCommand extends CommandRunner {
  private readonly logger = new Logger(AccountsBackfillCommand.name);
  constructor(private readonly control: ControlPrismaService) {
    super();
  }

  async run(): Promise<void> {
    const people = await this.control.membership.findMany({
      distinct: ['issuer', 'subject'],
      select: {
        issuer: true,
        subject: true,
        email: true,
        displayName: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'asc' },
    });
    const contacts = new Map(
      (
        await this.control.contactEmail.findMany({
          where: { verifiedAt: { not: null } },
          select: { issuer: true, subject: true, email: true },
        })
      ).map((c) => [`${c.issuer}|${c.subject}`, c.email]),
    );
    let n = 0;
    for (const p of people) {
      const verified = contacts.get(`${p.issuer}|${p.subject}`);
      const email = normalizeEmail(verified ?? p.email ?? '') ?? null;
      await this.control.$executeRaw`
        INSERT INTO accounts (id, issuer, subject, "displayName", "normalizedEmail", "emailVerified", "createdAt", "lastSeenAt")
        VALUES (gen_random_uuid()::text, ${p.issuer}, ${p.subject}, ${p.displayName ?? ''}, ${email}, ${!!verified}, ${p.createdAt}, ${p.createdAt})
        ON CONFLICT (issuer, subject) DO UPDATE SET
          "normalizedEmail" = COALESCE(accounts."normalizedEmail", EXCLUDED."normalizedEmail"),
          "displayName" = COALESCE(NULLIF(accounts."displayName", ''), EXCLUDED."displayName")`;
      n++;
    }
    this.logger.log(`account index: ${n} people`);
  }
}

/** `pnpm manar devices:index`: every host of every ACTIVE workspace into the staff device index. */
@Command({
  name: 'devices:index',
  description: 'Fill the staff device index from every workspace',
})
export class DevicesIndexCommand extends CommandRunner {
  private readonly logger = new Logger(DevicesIndexCommand.name);
  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly devices: DeviceIndexService,
  ) {
    super();
  }

  async run(): Promise<void> {
    const active = await this.control.tenant.findMany({
      where: { status: 'ACTIVE' },
      select: { id: true },
    });
    let n = 0;
    for (const t of active) {
      const db = await this.tenants.getClient(t.id);
      for (const h of await db.host.findMany()) {
        await this.devices.upsert(t.id, {
          hostId: h.id,
          machineId: h.machineId,
          hostname: h.hostname,
          os: h.os,
          status: h.status,
          ownerSubject: h.ownerSubject,
          lastSeenAt: h.lastSeenAt,
        });
        n++;
      }
    }
    this.logger.log(
      `device index: ${n} devices in ${active.length} workspaces`,
    );
  }
}
