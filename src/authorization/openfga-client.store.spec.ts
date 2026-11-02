import { describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { OpenFgaClientService } from './openfga-client.service';

type Store = { id: string; name: string; created_at: string };

/** Two replicas boot together: both list (none), both create; each must end on the same store. */
function racingClient(shared: Store[], mine: Store) {
  let listed = false;
  return {
    listStores: () => {
      const stores = listed ? shared : [];
      listed = true;
      return Promise.resolve({ stores, continuation_token: '' });
    },
    createStore: () => {
      shared.push(mine);
      return Promise.resolve({ id: mine.id });
    },
  };
}

const resolve = (client: unknown): Promise<string> => {
  const config = {
    get: (key: string) => (key === 'OPENFGA_STORE_NAME' ? 'manar' : undefined),
  } as unknown as ConfigService<AppConfig, true>;
  const service = new OpenFgaClientService(config) as unknown as {
    resolveStoreId(c: unknown): Promise<string>;
  };
  return service.resolveStoreId(client);
};

describe('OpenFGA store bootstrap with two replicas', () => {
  it('both replicas settle on the oldest store of that name', async () => {
    // Each replica's first list is empty (both list before either creates), then both create.
    const shared: Store[] = [];
    const older = {
      id: '01A',
      name: 'manar',
      created_at: '2026-11-03T00:00:00.100Z',
    };
    const newer = {
      id: '01B',
      name: 'manar',
      created_at: '2026-11-03T00:00:00.200Z',
    };
    const [first, second] = await Promise.all([
      resolve(racingClient(shared, older)),
      resolve(racingClient(shared, newer)),
    ]);
    expect(first).toBe('01A');
    expect(second).toBe('01A');
  });

  it('a single replica uses the store it created', async () => {
    const shared: Store[] = [];
    const id = await resolve(
      racingClient(shared, {
        id: '01C',
        name: 'manar',
        created_at: '2026-11-03T00:00:00Z',
      }),
    );
    expect(id).toBe('01C');
  });
});
