import { Injectable } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';

/** Fixed, known id — a deployment only ever has exactly one platform-wide switch (the same `AuditChainState`/`"singleton"` convention `prisma/tenant.prisma` already uses). */
const PLATFORM_KILL_SWITCH_SINGLETON_ID = 'singleton';

export interface PlatformKillSwitchState {
  active: boolean;
  reason: string | null;
  activatedBy: string | null;
  activatedAt: Date | null;
  deactivatedBy: string | null;
  deactivatedAt: Date | null;
}

const INACTIVE_DEFAULT: PlatformKillSwitchState = {
  active: false,
  reason: null,
  activatedBy: null,
  activatedAt: null,
  deactivatedBy: null,
  deactivatedAt: null,
};

/**
 * Reads/writes `PlatformKillSwitch` (control DB — see that model's doc
 * comment in `prisma/control.prisma` for why the platform scope lives
 * there rather than in any tenant database). Deliberately thin: no tenant
 * DB access of any kind, matching the spec's "`TenantDatabaseManager` or a
 * new thin `PlatformKillSwitchService` reads this without touching any
 * tenant DB" instruction. `isActive()` is on `AuthorizationService`'s and
 * `GrantService`'s hot/redemption paths (via `KillSwitchService.checkAll`)
 * — checked first, cheapest, applies to literally every tenant.
 */
@Injectable()
export class PlatformKillSwitchService {
  constructor(private readonly control: ControlPrismaService) {}

  async isActive(): Promise<boolean> {
    const row = await this.control.platformKillSwitch.findUnique({
      where: { id: PLATFORM_KILL_SWITCH_SINGLETON_ID },
    });
    return row?.active ?? false;
  }

  async getState(): Promise<PlatformKillSwitchState> {
    const row = await this.control.platformKillSwitch.findUnique({
      where: { id: PLATFORM_KILL_SWITCH_SINGLETON_ID },
    });
    return row ?? INACTIVE_DEFAULT;
  }

  /** Idempotent: activating an already-active switch just refreshes `reason`/`activatedBy`/`activatedAt`. */
  async activate(
    reason: string | undefined,
    activatedBy: string,
  ): Promise<PlatformKillSwitchState> {
    const now = new Date();
    return this.control.platformKillSwitch.upsert({
      where: { id: PLATFORM_KILL_SWITCH_SINGLETON_ID },
      create: {
        id: PLATFORM_KILL_SWITCH_SINGLETON_ID,
        active: true,
        reason: reason ?? null,
        activatedBy,
        activatedAt: now,
        deactivatedBy: null,
        deactivatedAt: null,
      },
      update: {
        active: true,
        reason: reason ?? null,
        activatedBy,
        activatedAt: now,
        deactivatedBy: null,
        deactivatedAt: null,
      },
    });
  }
}
