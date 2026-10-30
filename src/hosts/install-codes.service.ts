import { Injectable } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { normalizeInstallCode } from './install-code.util';
import { hashInstallKey } from './install-key.util';

export interface ResolvedInstallCode {
  tenantId: string;
  tenantSlug: string;
  installKeyId: string;
}

/**
 * Short code -> tenant + install key id, in the control DB (the public routes have no token to
 * find the tenant with). The code is itself the install key's secret, so only its hash is kept
 * here: nothing at rest can be turned into an install command. Rows go when the code is used,
 * when its key is revoked, and when they expire.
 */
@Injectable()
export class InstallCodesService {
  constructor(private readonly control: ControlPrismaService) {}

  async create(
    tenantId: string,
    code: string,
    installKeyId: string,
    expiresAt: Date,
  ): Promise<void> {
    await this.purgeExpired();
    await this.control.installCode.create({
      data: {
        codeHash: hashInstallKey(code),
        tenantId,
        installKeyId,
        expiresAt,
      },
    });
  }

  /** Null for a malformed, unknown or expired code (one answer for all three). */
  async find(raw: string): Promise<ResolvedInstallCode | null> {
    const code = normalizeInstallCode(raw);
    if (!code) return null;
    await this.purgeExpired();
    const row = await this.control.installCode.findUnique({
      where: { codeHash: hashInstallKey(code) },
      include: { tenant: { select: { slug: true, status: true } } },
    });
    if (!row || row.tenant.status !== 'ACTIVE') return null;
    return {
      tenantId: row.tenantId,
      tenantSlug: row.tenant.slug,
      installKeyId: row.installKeyId,
    };
  }

  /** The code was used (or its key is gone): it must not resolve again. */
  async deleteByCode(code: string): Promise<void> {
    await this.control.installCode.deleteMany({
      where: { codeHash: hashInstallKey(code) },
    });
  }

  async deleteByKeyId(installKeyId: string): Promise<void> {
    await this.control.installCode.deleteMany({ where: { installKeyId } });
  }

  private async purgeExpired(): Promise<void> {
    await this.control.installCode.deleteMany({
      where: { expiresAt: { lte: new Date() } },
    });
  }
}
