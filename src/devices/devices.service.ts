import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AuthContext } from '../auth/auth-context';
import type { AppConfig } from '../config/env.validation';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { EntitlementsService } from '../billing/entitlements.service';
import { InstallKeysService } from '../hosts/install-keys.service';
import { DEVICES_DEFAULTS } from './devices.config';
import { generateInstallCode } from '../hosts/install-code.util';
import { InstallCodesService } from '../hosts/install-codes.service';
import { oneLiners } from './install-scripts';

export const INSTALL_CODE_TTL_MS = 3_600_000; // 1 hour
const DEFAULT_GROUP = 'My devices';

@Injectable()
export class DevicesService {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly keys: InstallKeysService,
    private readonly codes: InstallCodesService,
    private readonly entitlements: EntitlementsService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  /**
   * "Add device": a one-hour, single-use install key plus the short code that stands for it.
   * The plan's device cap is checked here so the user hears about it before installing;
   * registration checks it again, under a lock, because that is what actually adds a device.
   */
  async createInstallCode(auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    const used = await client.host.count({
      where: { status: { in: ['PENDING', 'APPROVED'] } },
    });
    await this.entitlements.assertWithin(auth.tenant.id, 'devices', used);
    const group = await client.hostGroup.upsert({
      where: { name: DEFAULT_GROUP },
      update: {},
      create: { name: DEFAULT_GROUP },
    });
    const expiresAt = new Date(Date.now() + INSTALL_CODE_TTL_MS);
    // The short code is the install key's secret: the tenant side stores its hash like any key,
    // the control DB maps the same hash to the tenant, and nothing keeps the code itself.
    const code = generateInstallCode();
    const { key } = await this.keys.create(
      client,
      auth.tenant,
      { type: 'human', id: auth.user.id },
      {
        hostGroupId: group.id,
        label: 'Add device',
        maxUses: 1,
        expiresAt,
        rawKey: code,
      },
    );
    await this.codes.create(auth.tenant.id, code, key.id, expiresAt);
    const base =
      this.config.get('MANAR_CONSOLE_URL', { infer: true }) ??
      DEVICES_DEFAULTS.MANAR_CONSOLE_URL;
    return {
      code,
      /** The first-run screen matches the device it waits for by this id. */
      installKeyId: key.id,
      expiresAt: expiresAt.toISOString(),
      ...oneLiners(base, code),
    };
  }
}
