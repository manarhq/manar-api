import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ConfigService } from '@nestjs/config';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import { KeycloakAdminClient } from '../keycloak/keycloak-admin.client';
import { OpenBaoPkiClient } from './openbao-pki.client';

describe('hung upstreams fail after their timeout', () => {
  let server: Server;
  let url: string;
  beforeAll(async () => {
    server = createServer(() => undefined); // accepts and never answers
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });
  const config = (values: Record<string, unknown>) =>
    ({ get: (k: string) => values[k] }) as unknown as ConfigService<
      AppConfig,
      true
    >;

  it('OpenBao PKI: sign, revoke and CA chain', async () => {
    const client = new OpenBaoPkiClient(
      config({
        OPENBAO_ADDR: url,
        OPENBAO_TOKEN: 't',
        OPENBAO_PKI_INTERMEDIATE_PATH: 'pki_int',
        OPENBAO_PKI_AGENT_ROLE: 'r',
      }),
    );
    const before = OpenBaoPkiClient.REQUEST_TIMEOUT_MS;
    OpenBaoPkiClient.REQUEST_TIMEOUT_MS = 200;
    try {
      const started = Date.now();
      await expect(client.signVerbatim('csr', '1h')).rejects.toThrow();
      await expect(client.revoke('aa:bb')).rejects.toThrow();
      await expect(client.getCaChainPem()).rejects.toThrow();
      expect(Date.now() - started).toBeLessThan(3000);
    } finally {
      OpenBaoPkiClient.REQUEST_TIMEOUT_MS = before;
    }
  });

  it('Keycloak admin: the token request is bounded', async () => {
    const client = new KeycloakAdminClient(
      config({
        KEYCLOAK_BASE_URL: url,
        KEYCLOAK_ADMIN_USERNAME: 'a',
        KEYCLOAK_ADMIN_PASSWORD: 'b',
        KEYCLOAK_ADMIN_CLIENT_ID: 'admin-cli',
      }),
    );
    const before = KeycloakAdminClient.REQUEST_TIMEOUT_MS;
    KeycloakAdminClient.REQUEST_TIMEOUT_MS = 200;
    try {
      const started = Date.now();
      await expect(
        (
          client as unknown as {
            adminRequest: (m: string, p: string) => Promise<unknown>;
          }
        ).adminRequest('GET', '/x'),
      ).rejects.toThrow();
      expect(Date.now() - started).toBeLessThan(2000);
    } finally {
      KeycloakAdminClient.REQUEST_TIMEOUT_MS = before;
    }
  });
});
