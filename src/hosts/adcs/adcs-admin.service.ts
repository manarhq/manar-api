import { createHash } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../../generated/tenant-client/client';
import { AuditService } from '../../audit/audit.service';
import {
  AUDIT_EVENT_TYPES,
  type AuditActor,
} from '../../audit/audit-event-types';
import { OpenBaoKvClient } from '../../openbao/openbao-kv.client';
import { isLdapsUrl } from './ad-directory.client';
import {
  AdcsDirectoryService,
  adBindSecretPath,
} from './adcs-directory.service';
import { parsePem } from './cert-chain.util';
import { normalizeDn } from './ou.util';

/** The request is well-formed but not acceptable (maps to 400). */
export class AdcsConfigError extends Error {}

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

export interface AdcsSettingsInput {
  defaultHostGroupId: string;
  ldapsUrl?: string | null;
  baseDn?: string | null;
  bindDn?: string | null;
  serverCaPem?: string | null;
  /** Template OIDs accepted for key-less enrolment; empty accepts none. */
  allowedTemplateOids?: string[];
  /** Write-only. Goes to OpenBao KV; never stored in Postgres, never returned. */
  bindPassword?: string;
}

/** Customer CA trust, AD connection, OU rules and re-sync (docs/hosts.md). Every change audited. */
@Injectable()
export class AdcsAdminService {
  private readonly logger = new Logger(AdcsAdminService.name);

  constructor(
    private readonly audit: AuditService,
    private readonly kv: OpenBaoKvClient,
    private readonly directory: AdcsDirectoryService,
  ) {}

  private async audited<T>(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    eventType: string,
    change: (
      tx: Prisma.TransactionClient,
    ) => Promise<{ row: T; data: unknown }>,
  ): Promise<T> {
    const { row, publish } = await client.$transaction(async (tx) => {
      const { row: r, data } = await change(tx);
      const p = await this.audit.recordInTransaction(tx, tenantId, {
        eventType: eventType as never,
        actor,
        data,
      });
      return { row: r, publish: p };
    });
    publish();
    return row;
  }

  // Trusted customer CAs

  listCas(client: TenantPrismaClient) {
    return client.adcsTrustedCa.findMany({ orderBy: { createdAt: 'asc' } });
  }

  addCa(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: { label: string; certPem: string },
  ) {
    const cert = parsePem(input.certPem);
    const bc = cert.getExtension(x509.BasicConstraintsExtension);
    if (!bc?.ca) throw new AdcsConfigError('not a CA certificate');
    if (cert.notAfter < new Date()) {
      throw new AdcsConfigError('certificate is expired');
    }
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.ADCS_TRUSTED_CA_CHANGED,
      async (tx) => {
        const row = await tx.adcsTrustedCa.create({
          data: {
            label: input.label,
            certPem: cert.toString('pem'),
            subject: cert.subject,
            fingerprint: sha256(new Uint8Array(cert.rawData)),
            notAfter: cert.notAfter,
            createdBy: actor.id,
          },
        });
        return { row, data: { caId: row.id, before: null, after: row } };
      },
    );
  }

  removeCa(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
  ) {
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.ADCS_TRUSTED_CA_CHANGED,
      async (tx) => {
        const row = await tx.adcsTrustedCa.delete({ where: { id } });
        return { row, data: { caId: id, before: row, after: null } };
      },
    );
  }

  // Settings (AD connection)

  async getSettings(client: TenantPrismaClient, tenantId: string) {
    const row = await client.adcsSettings.findUnique({
      where: { id: 'default' },
    });
    if (!row) return null;
    const secret = await this.kv
      .readSecretIfPresent(adBindSecretPath(tenantId))
      .catch(() => null);
    return { ...row, bindPasswordSet: typeof secret?.password === 'string' };
  }

  async putSettings(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: AdcsSettingsInput,
  ) {
    const usesAd = Boolean(input.ldapsUrl);
    if (usesAd) {
      if (!isLdapsUrl(input.ldapsUrl!)) {
        throw new AdcsConfigError('ldapsUrl must be ldaps://host[:port]');
      }
      if (!input.baseDn || !input.bindDn || !input.serverCaPem) {
        throw new AdcsConfigError(
          'baseDn, bindDn and serverCaPem are required with ldapsUrl',
        );
      }
      if (normalizeDn(input.baseDn) === null) {
        throw new AdcsConfigError('baseDn is not a valid DN');
      }
      parsePem(input.serverCaPem);
      const stored = await client.adcsSettings.findUnique({
        where: { id: 'default' },
      });
      const secret = await this.kv
        .readSecretIfPresent(adBindSecretPath(tenantId))
        .catch(() => null);
      // The stored password is only ever sent to the server it was set for.
      // Any change of target needs the password again, which replaces the old one.
      const targetChanged =
        !stored ||
        stored.ldapsUrl !== input.ldapsUrl ||
        stored.bindDn !== input.bindDn ||
        stored.serverCaPem !== input.serverCaPem;
      if (
        !input.bindPassword &&
        (targetChanged || typeof secret?.password !== 'string')
      ) {
        throw new AdcsConfigError(
          'bindPassword is required when ldapsUrl, bindDn or serverCaPem changes',
        );
      }
    }
    // The password goes to KV first, so a settings row never points at nothing.
    if (input.bindPassword) {
      await this.kv.writeSecret(adBindSecretPath(tenantId), {
        password: input.bindPassword,
      });
    }
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.ADCS_SETTINGS_CHANGED,
      async (tx) => {
        const before = await tx.adcsSettings.findUnique({
          where: { id: 'default' },
        });
        const data = {
          defaultHostGroupId: input.defaultHostGroupId,
          ldapsUrl: input.ldapsUrl ?? null,
          baseDn: input.baseDn ?? null,
          bindDn: input.bindDn ?? null,
          serverCaPem: input.serverCaPem ?? null,
          allowedTemplateOids: input.allowedTemplateOids ?? [],
        };
        const row = await tx.adcsSettings.upsert({
          where: { id: 'default' },
          create: { id: 'default', ...data },
          update: data,
        });
        return {
          row,
          data: {
            before,
            after: row,
            // Never the password itself.
            bindPasswordChanged: Boolean(input.bindPassword),
          },
        };
      },
    );
  }

  // OU rules

  listOuRules(client: TenantPrismaClient) {
    return client.adOuRule.findMany({ orderBy: { ouDnKey: 'asc' } });
  }

  createOuRule(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    input: { ouDn: string; hostGroupId: string },
  ) {
    const key = normalizeDn(input.ouDn);
    if (!key) throw new AdcsConfigError('ouDn is not a valid DN');
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.AD_OU_RULE_CHANGED,
      async (tx) => {
        const row = await tx.adOuRule.create({
          data: {
            ouDn: input.ouDn.trim(),
            ouDnKey: key,
            hostGroupId: input.hostGroupId,
          },
        });
        return { row, data: { ruleId: row.id, before: null, after: row } };
      },
    );
  }

  updateOuRule(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
    input: { hostGroupId: string },
  ) {
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.AD_OU_RULE_CHANGED,
      async (tx) => {
        const before = await tx.adOuRule.findUnique({ where: { id } });
        const row = await tx.adOuRule.update({
          where: { id },
          data: { hostGroupId: input.hostGroupId },
        });
        return { row, data: { ruleId: id, before, after: row } };
      },
    );
  }

  deleteOuRule(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
  ) {
    return this.audited(
      client,
      tenantId,
      actor,
      AUDIT_EVENT_TYPES.AD_OU_RULE_CHANGED,
      async (tx) => {
        const row = await tx.adOuRule.delete({ where: { id } });
        return { row, data: { ruleId: id, before: row, after: null } };
      },
    );
  }

  // Re-sync

  /**
   * Re-reads the OU of every ADCS host from AD and moves hosts whose OU now
   * maps to another group. AD unreachable: nothing changes (the run stops at
   * the first failure and says so). A computer AD does not find, or whose OU
   * is unmapped, stays where it is. Status is never touched.
   */
  async resync(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
  ) {
    const hosts = await client.host.findMany({
      where: {
        enrolmentMethod: 'ADCS',
        status: { in: ['PENDING', 'APPROVED'] },
        adcsDnsName: { not: null },
      },
      orderBy: { createdAt: 'asc' },
      take: 5000,
    });
    const result = {
      status: 'ok' as 'ok' | 'ad_unreachable' | 'not_configured',
      checked: 0,
      moved: 0,
      unchanged: 0,
      notFound: 0,
      unmapped: 0,
    };
    for (const host of hosts) {
      const found = await this.directory.resolve(
        client,
        tenantId,
        host.adcsDnsName!,
      );
      if (found.state === 'not_configured' || found.state === 'unavailable') {
        result.status =
          found.state === 'unavailable' ? 'ad_unreachable' : 'not_configured';
        break;
      }
      result.checked += 1;
      if (found.state === 'not_found') {
        result.notFound += 1;
        continue;
      }
      if (!found.hostGroupId) {
        result.unmapped += 1;
        continue;
      }
      if (found.hostGroupId === host.hostGroupId) {
        result.unchanged += 1;
        await client.host.update({
          where: { id: host.id },
          data: { adDn: found.dn, adDnCheckedAt: new Date() },
        });
        continue;
      }
      const publish = await client.$transaction(async (tx) => {
        const { count } = await tx.host.updateMany({
          where: {
            id: host.id,
            hostGroupId: host.hostGroupId,
            status: host.status,
          },
          data: {
            hostGroupId: found.hostGroupId!,
            adDn: found.dn,
            adDnCheckedAt: new Date(),
          },
        });
        if (count !== 1) return null;
        return this.audit.recordInTransaction(tx, tenantId, {
          eventType: AUDIT_EVENT_TYPES.HOST_GROUP_MOVED,
          actor,
          data: {
            hostId: host.id,
            fromHostGroupId: host.hostGroupId,
            toHostGroupId: found.hostGroupId,
            adDn: found.dn,
            source: 'ad_resync',
          },
        });
      });
      if (publish) {
        publish();
        result.moved += 1;
      }
    }
    const done = await client.$transaction(async (tx) =>
      this.audit.recordInTransaction(tx, tenantId, {
        eventType: AUDIT_EVENT_TYPES.ADCS_RESYNC_RUN,
        actor,
        data: result,
      }),
    );
    done();
    if (result.status !== 'ok') {
      this.logger.warn(`AD re-sync for tenant ${tenantId}: ${result.status}`);
    }
    return result;
  }
}
