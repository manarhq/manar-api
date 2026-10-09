import { createServer, type Server, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';
import { OpenFgaClient } from '@openfga/sdk';
import { afterEach, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { OpenFgaClientService } from './openfga-client.service';

/**
 * Load-test finding (9 Oct): with OpenFGA down, each decision waited about
 * 2 s in the SDK's retries, and an OpenFGA that accepts connections but
 * never answers held a decision forever. A check is bounded by
 * OPENFGA_CHECK_TIMEOUT_MS, retries included.
 */
const TIMEOUT_MS = 300;
const TUPLE = { user: 'agent:a', relation: 'can_use', object: 'grant:g' };

function serviceAgainst(apiUrl: string): OpenFgaClientService {
  const config = {
    get: (key: string) =>
      key === 'OPENFGA_CHECK_TIMEOUT_MS' ? TIMEOUT_MS : undefined,
  } as unknown as ConfigService<AppConfig, true>;
  const service = new OpenFgaClientService(config);
  // As if onModuleInit had resolved the store and model before the outage.
  Object.assign(service, {
    client: new OpenFgaClient({
      apiUrl,
      storeId: '01HZZZZZZZZZZZZZZZZZZZZZZZ',
    }),
    _storeId: '01HZZZZZZZZZZZZZZZZZZZZZZZ',
    _authorizationModelId: '01HZZZZZZZZZZZZZZZZZZZZZZZ',
  });
  return service;
}

async function elapsedUntilRejected(work: Promise<unknown>): Promise<number> {
  const started = Date.now();
  const outcome = await Promise.race([
    work.then(
      () => 'resolved',
      () => 'rejected',
    ),
    new Promise((r) => setTimeout(() => r('hung'), 3_000)),
  ]);
  expect(outcome).toBe('rejected');
  return Date.now() - started;
}

describe('OpenFgaClientService.check is bounded', () => {
  const servers: Server[] = [];
  const sockets: Socket[] = [];
  afterEach(() => {
    sockets.splice(0).forEach((s) => s.destroy());
    servers.splice(0).forEach((s) => s.close());
  });

  it('an OpenFGA that accepts and never answers rejects within the timeout', async () => {
    const blackHole = createServer((s) => sockets.push(s));
    servers.push(blackHole);
    await new Promise<void>((r) => blackHole.listen(0, '127.0.0.1', r));
    const { port } = blackHole.address() as AddressInfo;

    const ms = await elapsedUntilRejected(
      serviceAgainst(`http://127.0.0.1:${port}`).check(TUPLE),
    );
    expect(ms).toBeLessThan(TIMEOUT_MS + 300);
  });

  it('an OpenFGA that refuses connections rejects without the default retry backoff', async () => {
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const { port } = probe.address() as AddressInfo;
    await new Promise((r) => probe.close(r)); // nothing listens there now

    const ms = await elapsedUntilRejected(
      serviceAgainst(`http://127.0.0.1:${port}`).check(TUPLE),
    );
    expect(ms).toBeLessThan(TIMEOUT_MS + 300);
  });
});
