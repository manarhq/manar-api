import { describe, expect, it, vi } from 'vitest';
import { TenantSettingsService } from './tenant-settings.service';

function make() {
  const update = vi.fn().mockResolvedValue({
    id: 't1',
    slug: 't1',
    name: 'T',
    residency: 'UAE',
    allowExternalAi: false,
    allowOutboundTelemetry: false,
    allowCloudStorage: false,
    approvalsAdminsOnly: false,
    keycloakIssuerUrl: null,
    keycloakClientId: null,
  });
  const control = { tenant: { update, findUnique: vi.fn() } };
  const audit = { record: vi.fn().mockResolvedValue(undefined) };
  const tenants = { getClient: vi.fn().mockResolvedValue({}) };
  const config = { get: vi.fn() };
  const service = new TenantSettingsService(
    control as never,
    audit as never,
    tenants as never,
    config as never,
  );
  return { service, update, audit };
}

describe('TenantSettingsService.updateSettings', () => {
  it('records an owner-set allowExternalAi as a choice, so no default change overrides it', async () => {
    const { service, update } = make();
    await service.updateSettings('t1', 'u1', { allowExternalAi: false });
    expect((update.mock.calls[0]![0] as { data: object }).data).toMatchObject({
      allowExternalAi: false,
      allowExternalAiChosen: true,
    });
  });

  it('leaves the choice alone when allowExternalAi is not part of the change', async () => {
    const { service, update } = make();
    await service.updateSettings('t1', 'u1', { allowCloudStorage: true });
    expect(
      (update.mock.calls[0]![0] as { data: object }).data,
    ).not.toHaveProperty('allowExternalAiChosen');
  });

  it('refuses the change when its audit event does not land: nothing is written', async () => {
    const { service, update, audit } = make();
    audit.record.mockRejectedValue(new Error('audit store down'));
    await expect(
      service.updateSettings('t1', 'u1', { allowExternalAi: false }),
    ).rejects.toMatchObject({ status: 503 });
    expect(update).not.toHaveBeenCalled();
  });

  it('writes the audit event before the change', async () => {
    const { service, update, audit } = make();
    await service.updateSettings('t1', 'u1', { allowExternalAi: true });
    expect(audit.record.mock.invocationCallOrder[0]!).toBeLessThan(
      update.mock.invocationCallOrder[0]!,
    );
  });
});
