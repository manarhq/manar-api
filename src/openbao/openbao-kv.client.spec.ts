import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ConfigService } from '@nestjs/config';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import { OpenBaoKvClient } from './openbao-kv.client';

describe('OpenBaoKvClient', () => {
  let server: Server;
  let url: string;

  beforeAll(async () => {
    // Accepts the request and never answers: a hung OpenBao.
    server = createServer(() => undefined);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });

  it('fails a call to a hung OpenBao after its timeout instead of waiting forever', async () => {
    const values: Record<string, unknown> = {
      OPENBAO_ADDR: url,
      OPENBAO_TOKEN: 'test-token',
      OPENBAO_KV_MOUNT_PATH: 'secret',
    };
    const client = new OpenBaoKvClient({
      get: (k: string) => values[k],
    } as unknown as ConfigService<AppConfig, true>);
    const before = OpenBaoKvClient.REQUEST_TIMEOUT_MS;
    OpenBaoKvClient.REQUEST_TIMEOUT_MS = 200;
    try {
      const started = Date.now();
      await expect(client.readCustomMetadata('tools/x')).rejects.toThrow();
      expect(Date.now() - started).toBeLessThan(2000);
    } finally {
      OpenBaoKvClient.REQUEST_TIMEOUT_MS = before;
    }
  });
});
