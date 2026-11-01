import { describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
import {
  DcrCleanupService,
  UNCONFIRMED_TTL_MS,
  UNSCOPED_TTL_MS,
} from './dcr-cleanup.service';

const CB = ['https://chatgpt.com/connector_platform_oauth_redirect'];
const client = (id: string, extra: Record<string, unknown> = {}) => ({
  id: `u-${id}`,
  clientId: id,
  redirectUris: CB,
  attributes: {} as Record<string, string>,
  ...extra,
});

function setup(clients: ReturnType<typeof client>[]) {
  const kc = {
    listClients: vi.fn().mockResolvedValue(clients),
    updateClient: vi.fn(
      (
        _r: string,
        id: string,
        patch: { attributes: Record<string, string> },
      ) => {
        Object.assign(
          clients.find((c) => c.clientId === id)!.attributes,
          patch.attributes,
        );
        return Promise.resolve();
      },
    ),
    deleteById: vi.fn().mockResolvedValue(undefined),
  };
  const config = {
    get: (k: string) =>
      ({
        MANAR_MCP_ENABLED: 'true',
        MANAR_MCP_HOST: 'mcp.manar.test',
        MANAR_MCP_SHARED_ISSUER: 'https://auth.manar.test/realms/manar',
        MANAR_MCP_CHATGPT_ENABLED: 'true',
        KEYCLOAK_CLIENT_ID: 'manar-api',
      })[k],
  } as unknown as ConfigService<AppConfig, true>;
  return {
    kc,
    svc: new DcrCleanupService(config, kc as unknown as KeycloakAdminClient),
  };
}

describe('DcrCleanupService.sweep', () => {
  it('marks first, then deletes unscoped after 15 min and unconfirmed scoped after 6 h; never pending, confirmed, console or foreign-host clients', async () => {
    const all = [
      client('unscoped'),
      client('scoped', {
        defaultClientScopes: ['basic'],
        optionalClientScopes: ['manar-mcp-t-a'],
      }),
      client('pending', { attributes: { 'manar.dcr.state': 'pending' } }),
      client('confirmed', { attributes: { 'manar.dcr.state': 'confirmed' } }),
      client('manar-api'),
      client('manar-cloud-t-a'),
      client('foreign', { redirectUris: ['https://evil.example/cb'] }),
    ];
    const { svc, kc } = setup(all);
    const t0 = 1_000_000;
    expect(await svc.sweep(t0)).toEqual([]);
    expect(all[0]!.attributes['manar.dcr.first_seen']).toBe(String(t0));
    expect(all[2]!.attributes['manar.dcr.first_seen']).toBeUndefined();
    expect(await svc.sweep(t0 + UNSCOPED_TTL_MS - 1)).toEqual([]);
    expect(await svc.sweep(t0 + UNSCOPED_TTL_MS)).toEqual(['unscoped']);
    expect(await svc.sweep(t0 + UNCONFIRMED_TTL_MS)).toEqual([
      'unscoped',
      'scoped',
    ]);
    expect(kc.deleteById).not.toHaveBeenCalledWith(
      'manar',
      'clients/u-pending',
    );
    expect(kc.deleteById).toHaveBeenCalledTimes(3);
  });
});
