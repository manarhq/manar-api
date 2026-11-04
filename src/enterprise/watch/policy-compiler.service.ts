import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import { entConfig } from '../common/ent-config';

/**
 * The WATCH policy document for one device (shape: manar-browser src/core/policy.ts). This first
 * slice carries branding, language, the approver and the unreadable-file rule; rules, sites and
 * grants are added by the rules and exceptions tasks (plan Tasks 12 and 13). The version is a hash
 * of the content, so a long-poll answers as soon as anything that matters changes.
 */
@Injectable()
export class PolicyCompilerService {
  async forDevice(
    db: TenantPrismaClient,
    tenantId: string,
    publicSlug: string,
    personId: string | null,
  ) {
    const settings = await db.entSettings.findUnique({ where: { id: 1 } });
    const person = personId
      ? await db.entPerson.findUnique({
          where: { id: personId },
          include: { manager: true },
        })
      : null;
    const language: 'en' | 'ar' = (
      person?.preferredLanguage ??
      settings?.defaultLanguage ??
      'en'
    )
      .toLowerCase()
      .startsWith('ar')
      ? 'ar'
      : 'en';
    const manager = person?.manager?.accountEnabled ? person.manager : null;
    const logo =
      settings?.logo && settings.logoType
        ? `data:${settings.logoType};base64,${Buffer.from(settings.logo).toString('base64')}`
        : null;
    const body = {
      tenantId,
      personId,
      org: {
        nameEn: settings?.orgNameEn ?? '',
        nameAr: settings?.orgNameAr ?? '',
        short: settings?.orgShort ?? '',
        logoDataUrl: logo,
        seeUrl: `${entConfig().consoleUrl}/${language}/see/${publicSlug}`,
      },
      language,
      rules: [] as unknown[],
      sites: [] as unknown[],
      grants: [] as unknown[],
      unreadableFile:
        settings?.unreadableFile === 'ALLOW_FLAG' ? 'ALLOW_FLAG' : 'ASK',
      keywords: [] as string[],
      approver: manager
        ? {
            name: manager.displayName,
            relation: 'manager' as const,
            channel: 'teams' as const,
          }
        : {
            name: '',
            relation: 'security' as const,
            channel: 'teams' as const,
          },
    };
    const version = createHash('sha256')
      .update(JSON.stringify(body))
      .digest('hex')
      .slice(0, 16);
    return { version, issuedAt: new Date().toISOString(), ...body };
  }
}
