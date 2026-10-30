import { Injectable } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { generateInstallCode, normalizeInstallCode } from './install-code.util';

export interface ResolvedInstallCode {
  tenantId: string;
  installKey: string;
}

/**
 * Short code -> tenant + install key, in the control DB (the public `/i/<code>` route has no
 * token to find the tenant with). Looking a code up never uses the key: only registration does.
 */
@Injectable()
export class InstallCodesService {
  constructor(private readonly control: ControlPrismaService) {}

  async create(
    tenantId: string,
    installKey: string,
    expiresAt: Date,
  ): Promise<string> {
    // Expired rows hold a dead key; drop them as we go.
    await this.control.installCode.deleteMany({
      where: { expiresAt: { lt: new Date(Date.now() - 24 * 3_600_000) } },
    });
    for (let attempt = 0; attempt < 5; attempt++) {
      const code = generateInstallCode();
      try {
        await this.control.installCode.create({
          data: { code, tenantId, installKey, expiresAt },
        });
        return code;
      } catch (error) {
        if ((error as { code?: string }).code !== 'P2002') throw error; // not a code collision
      }
    }
    throw new Error('could not allocate an install code');
  }

  /** Null for a malformed, unknown or expired code (one answer for all three). */
  async find(raw: string): Promise<ResolvedInstallCode | null> {
    const code = normalizeInstallCode(raw);
    if (!code) return null;
    const row = await this.control.installCode.findUnique({ where: { code } });
    if (!row || row.expiresAt.getTime() <= Date.now()) return null;
    return { tenantId: row.tenantId, installKey: row.installKey };
  }
}
