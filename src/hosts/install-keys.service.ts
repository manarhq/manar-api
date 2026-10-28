import { Injectable, Logger } from '@nestjs/common';
import type {
  InstallKey,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES, type AuditActor } from '../audit/audit-event-types';
import {
  generateInstallKey,
  hashInstallKey,
  ipAllowed,
  isValidCidr,
} from './install-key.util';

/** One error for every refusal, so a caller learns nothing about why. */
export class InstallKeyInvalidError extends Error {
  constructor() {
    super('install key is not valid');
  }
}

export class HostGroupNotFoundError extends Error {}

/** A range that isn't `network/prefix`: refused rather than silently ignored. */
export class InvalidCidrError extends Error {}

export interface CreateInstallKeyInput {
  hostGroupId: string;
  label: string;
  allowedCidrs?: string[];
  maxUses?: number;
  expiresAt?: Date;
}

/**
 * Install keys (docs/hosts.md): registration-only secrets scoped to one host
 * group. The raw key is returned once by `create` and stored only as its
 * SHA-256. Creating and revoking are audited in the same transaction.
 */
@Injectable()
export class InstallKeysService {
  private readonly logger = new Logger(InstallKeysService.name);

  constructor(private readonly audit: AuditService) {}

  async create(
    client: TenantPrismaClient,
    tenant: { id: string; slug: string },
    actor: AuditActor,
    input: CreateInstallKeyInput,
  ): Promise<{ key: InstallKey; raw: string }> {
    const bad = (input.allowedCidrs ?? []).filter((c) => !isValidCidr(c));
    if (bad.length > 0) throw new InvalidCidrError(bad.join(', '));
    const raw = generateInstallKey(tenant.slug);
    const [key, publish] = await client.$transaction(async (tx) => {
      const group = await tx.hostGroup.findUnique({
        where: { id: input.hostGroupId },
      });
      if (!group) throw new HostGroupNotFoundError(input.hostGroupId);
      const created = await tx.installKey.create({
        data: {
          hostGroupId: input.hostGroupId,
          keyHash: hashInstallKey(raw),
          label: input.label,
          allowedCidrs: input.allowedCidrs ?? [],
          maxUses: input.maxUses ?? null,
          expiresAt: input.expiresAt ?? null,
          createdBy: actor.id,
        },
      });
      const done = await this.audit.recordInTransaction(tx, tenant.id, {
        eventType: AUDIT_EVENT_TYPES.INSTALL_KEY_CREATED,
        actor,
        data: {
          installKeyId: created.id,
          hostGroupId: created.hostGroupId,
          label: created.label,
          allowedCidrs: created.allowedCidrs,
          maxUses: created.maxUses,
          expiresAt: created.expiresAt?.toISOString() ?? null,
        },
      });
      return [created, done] as const;
    });
    publish();
    return { key, raw };
  }

  async revoke(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
  ): Promise<InstallKey | null> {
    const result = await client.$transaction(async (tx) => {
      const key = await tx.installKey.findUnique({ where: { id } });
      if (!key) return null;
      if (key.revokedAt) return { key, publish: () => undefined };
      const revoked = await tx.installKey.update({
        where: { id },
        data: { revokedAt: new Date() },
      });
      const publish = await this.audit.recordInTransaction(tx, tenantId, {
        eventType: AUDIT_EVENT_TYPES.INSTALL_KEY_REVOKED,
        actor,
        data: { installKeyId: id, hostGroupId: key.hostGroupId },
      });
      return { key: revoked, publish };
    });
    result?.publish();
    return result?.key ?? null;
  }

  /**
   * Uses the key once. The range check comes first; the count, expiry and
   * revocation are checked by the one conditional UPDATE that takes the
   * use, so concurrent registrations can never exceed `maxUses`.
   */
  async consume(
    client: TenantPrismaClient,
    raw: string,
    ip: string,
  ): Promise<InstallKey> {
    const keyHash = hashInstallKey(raw);
    const key = await client.installKey.findUnique({ where: { keyHash } });
    if (!key || !ipAllowed(ip, key.allowedCidrs)) {
      this.logger.warn(
        `install key refused (${key ? `key ${key.id}: address outside its ranges` : 'unknown key'})`,
      );
      throw new InstallKeyInvalidError();
    }
    const [used] = await client.$queryRaw<InstallKey[]>`
      UPDATE "install_keys"
      SET "uses" = "uses" + 1, "updatedAt" = now()
      WHERE "keyHash" = ${keyHash}
        AND "revokedAt" IS NULL
        AND ("expiresAt" IS NULL OR "expiresAt" > (now() AT TIME ZONE 'UTC'))
        AND ("maxUses" IS NULL OR "uses" < "maxUses")
      RETURNING *
    `;
    if (!used) {
      this.logger.warn(
        `install key ${key.id} refused: revoked, expired or used up`,
      );
      throw new InstallKeyInvalidError();
    }
    return used;
  }
}
