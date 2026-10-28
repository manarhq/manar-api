import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import { OpenBaoKvClient } from '../../openbao/openbao-kv.client';
import { AdDirectory, AdUnreachableError } from './ad-directory.client';
import { longestOuMatch } from './ou.util';

/** Where the AD bind password lives: OpenBao KV, per tenant. Never Postgres, never a log. */
export const adBindSecretPath = (tenantId: string) =>
  `adcs/${tenantId}/ad-bind`;

export type OuResolution =
  | { state: 'resolved'; dn: string; hostGroupId: string | null }
  | { state: 'not_found' }
  | { state: 'unavailable' }
  | { state: 'not_configured' };

/**
 * Finds a computer's OU in the customer's AD and maps it to a host group.
 * Any failure (settings missing, password unreadable, AD unreachable) is
 * `unavailable`/`not_configured`: callers change nothing and approve
 * nothing.
 */
@Injectable()
export class AdcsDirectoryService {
  private readonly logger = new Logger(AdcsDirectoryService.name);

  constructor(
    private readonly directory: AdDirectory,
    private readonly kv: OpenBaoKvClient,
  ) {}

  async resolve(
    client: TenantPrismaClient,
    tenantId: string,
    dnsName: string,
  ): Promise<OuResolution> {
    const settings = await client.adcsSettings.findUnique({
      where: { id: 'default' },
    });
    if (
      !settings?.ldapsUrl ||
      !settings.baseDn ||
      !settings.bindDn ||
      !settings.serverCaPem
    ) {
      return { state: 'not_configured' };
    }
    try {
      const secret = await this.kv.readSecretIfPresent(
        adBindSecretPath(tenantId),
      );
      const password = secret?.password;
      if (typeof password !== 'string' || password.length === 0) {
        this.logger.warn(`AD bind password missing for tenant ${tenantId}`);
        return { state: 'unavailable' };
      }
      const found = await this.directory.findComputer(
        {
          ldapsUrl: settings.ldapsUrl,
          baseDn: settings.baseDn,
          bindDn: settings.bindDn,
          serverCaPem: settings.serverCaPem,
          password,
        },
        dnsName,
      );
      if (!found.found) return { state: 'not_found' };
      const rules = await client.adOuRule.findMany();
      const rule = longestOuMatch(found.dn, rules);
      return {
        state: 'resolved',
        dn: found.dn,
        hostGroupId: rule?.hostGroupId ?? null,
      };
    } catch (error) {
      this.logger.warn(
        `AD lookup unavailable for tenant ${tenantId}: ${
          error instanceof AdUnreachableError ? error.message : 'internal error'
        }`,
      );
      return { state: 'unavailable' };
    }
  }
}
