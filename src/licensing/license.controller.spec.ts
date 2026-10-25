import { GUARDS_METADATA } from '@nestjs/common/constants';
import { describe, expect, it } from 'vitest';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { REQUIRED_ROLES_KEY } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { PlatformAuthGuard } from '../platform/platform-auth.guard';
import type { LicenseStatus } from './license';
import {
  PlatformLicenseController,
  TenantLicenseController,
} from './license.controller';
import type { LicenseService } from './license.service';

const full: LicenseStatus = {
  status: 'over_limit',
  reason: null,
  deployment: 'customer',
  kid: 'k1',
  licenseId: 'LIC-9',
  customer: 'Customer name',
  issuedAt: '2026-01-01T00:00:00.000Z',
  notBefore: '2026-01-01T00:00:00.000Z',
  expiresAt: '2027-01-01T00:00:00.000Z',
  daysLeft: 68,
  limits: { agents: 10, tenants: 2 },
  features: ['packs'],
  usage: { agents: 14, tenants: 2 },
  overLimit: ['agents'],
  checkedAt: '2026-10-25T00:00:00.000Z',
};
const license = {
  status: () => Promise.resolve(full),
} as unknown as LicenseService;

describe('licence endpoints', () => {
  it('GET /platform/v1/license is behind the platform guard and returns the full status', async () => {
    expect(
      Reflect.getMetadata(GUARDS_METADATA, PlatformLicenseController),
    ).toEqual([PlatformAuthGuard]);
    await expect(
      new PlatformLicenseController(license).status(),
    ).resolves.toEqual(full);
  });

  it('GET /tenant/license needs a tenant admin role', () => {
    expect(
      Reflect.getMetadata(GUARDS_METADATA, TenantLicenseController),
    ).toEqual([JwtAuthGuard, RolesGuard]);
    expect(
      Reflect.getMetadata(REQUIRED_ROLES_KEY, TenantLicenseController),
    ).toEqual(['TENANT_OWNER', 'SECURITY_ADMIN']);
  });

  it('GET /tenant/license gives a banner what it needs and nothing about other tenants', async () => {
    const view = await new TenantLicenseController(license).view();
    expect(view).toEqual({
      status: 'over_limit',
      deployment: 'customer',
      expiresAt: '2027-01-01T00:00:00.000Z',
      daysLeft: 68,
      overLimit: true,
    });
    for (const leaked of [
      'usage',
      'limits',
      'customer',
      'licenseId',
      'kid',
      'features',
    ])
      expect(view).not.toHaveProperty(leaked);
  });
});
