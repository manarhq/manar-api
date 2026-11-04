import { NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { EnterpriseGateService } from './enterprise-gate.service';

const make = (o: {
  status?: string | null;
  enterprise?: boolean;
  profile?: boolean;
  catalogFails?: boolean;
  dbFails?: boolean;
}) => {
  const control = {
    tenant: {
      findUnique: () => {
        if (o.dbFails) throw new Error('db down');
        return o.status === null ? null : { status: o.status ?? 'ACTIVE' };
      },
    },
    enterpriseProfile: {
      findUnique: () =>
        Promise.resolve(
          o.profile === false
            ? null
            : { tenantId: 't', sector: 'GOVERNMENT', publicSlug: 'mds' },
        ),
    },
  };
  const catalog = {
    state: () =>
      o.catalogFails
        ? Promise.reject(new Error('malformed catalog row'))
        : Promise.resolve({ features: { enterprise: o.enterprise ?? true } }),
  };
  return new EnterpriseGateService(control as never, catalog as never);
};

describe('EnterpriseGateService', () => {
  it('on: flag on, profile present, tenant active', async () => {
    await expect(make({}).requireEnabled('t')).resolves.toEqual({
      tenantId: 't',
      sector: 'GOVERNMENT',
      publicSlug: 'mds',
    });
  });
  it('off (404) when the flag is off, by default, or without a profile, or not active', async () => {
    await expect(
      make({ enterprise: false }).requireEnabled('t'),
    ).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      make({ profile: false }).requireEnabled('t'),
    ).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      make({ status: 'SUSPENDED' }).requireEnabled('t'),
    ).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      make({ status: null }).requireEnabled('t'),
    ).rejects.toBeInstanceOf(NotFoundException);
  });
  it('fails closed (503) when the catalog or the control DB cannot be read', async () => {
    await expect(
      make({ catalogFails: true }).requireEnabled('t'),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    await expect(
      make({ dbFails: true }).requireEnabled('t'),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});
