import { APP_GUARD } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InstallCodesService } from '../hosts/install-codes.service';
import { INSTALL_FETCH_LIMIT, InstallController } from './install.controller';

const SHA = (c: string) => c.repeat(64);
const settings: Record<string, string | undefined> = {
  MANAR_EDGE_VERSION: 'v0.1.0',
  MANAR_EDGE_SHA256_WINDOWS_AMD64: SHA('a'),
  MANAR_EDGE_SHA256_LINUX_AMD64: SHA('b'),
  MANAR_EDGE_SHA256_LINUX_ARM64: SHA('c'),
};

describe('GET /i/:code (public)', () => {
  let app: NestFastifyApplication;
  const codes = {
    find: vi.fn(),
    deleteByCode: vi.fn(),
    deleteByKeyId: vi.fn(),
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    Object.assign(settings, { MANAR_EDGE_VERSION: 'v0.1.0' });
    codes.find.mockImplementation((raw: string) =>
      Promise.resolve(
        raw.toUpperCase() === 'ABCDEFGH23'
          ? { tenantId: 't1', tenantSlug: 'me-1', installKeyId: 'k1' }
          : null,
      ),
    );
    const moduleRef = await Test.createTestingModule({
      imports: [
        ThrottlerModule.forRoot({
          throttlers: [{ name: 'human', ttl: 60_000, limit: 1000 }],
        }),
      ],
      controllers: [InstallController],
      providers: [
        { provide: InstallCodesService, useValue: codes },
        {
          provide: ConfigService,
          useValue: { get: (k: string) => settings[k] },
        },
        { provide: APP_GUARD, useClass: ThrottlerGuard },
      ],
    }).compile();
    app = moduleRef.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterEach(() => app.close());

  const get = (url: string) => app.inject({ method: 'GET', url });

  it('serves the PowerShell script with the code embedded, as no-store text', async () => {
    const res = await get('/i/ABCDEFGH23');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toContain("install --code 'ABCDEFGH23' --tenant 'me-1'");
    expect(res.body).toContain(SHA('a'));
  });

  it('serves the sh script at .sh', async () => {
    const res = await get('/i/abcdefgh23.sh');
    expect(res.statusCode).toBe(200);
    expect(res.body.startsWith('#!/bin/sh')).toBe(true);
    expect(res.body).toContain("install --code 'ABCDEFGH23'");
  });

  it('fetching twice does not consume the code', async () => {
    const a = await get('/i/ABCDEFGH23');
    const b = await get('/i/ABCDEFGH23');
    expect(a.body).toBe(b.body);
    expect(a.body).toContain('ABCDEFGH23');
    expect(codes.deleteByCode).not.toHaveBeenCalled();
    expect(codes.deleteByKeyId).not.toHaveBeenCalled();
  });

  it('an unknown or malformed code gets a script with a clear error, not a 500', async () => {
    for (const url of [
      '/i/ZZZZZZZZ22',
      '/i/nope',
      '/i/ZZZZZZZZ22.sh',
      '/i/%27%3Bcalc',
    ]) {
      const res = await get(url);
      expect(res.statusCode).toBe(200);
      expect(res.body).toContain('not valid or has expired');
      expect(res.body).not.toContain('install --code');
    }
  });

  it('when no release is configured it says the installer is not available yet', async () => {
    settings.MANAR_EDGE_VERSION = undefined;
    const res = await get('/i/ABCDEFGH23');
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('not available yet');
    expect(res.body).not.toContain('ABCDEFGH23');
  });

  it('serves the uninstall one-liners without a code', async () => {
    expect((await get('/i/uninstall')).body).toContain('manar-edge.exe');
    expect((await get('/i/uninstall.sh')).body).toContain(
      '/usr/local/bin/manar-edge',
    );
    expect(codes.find).not.toHaveBeenCalled();
  });

  it('is rate limited per address', async () => {
    for (let i = 0; i < INSTALL_FETCH_LIMIT; i++) {
      expect((await get('/i/ABCDEFGH23')).statusCode).toBe(200);
    }
    expect((await get('/i/ABCDEFGH23')).statusCode).toBe(429);
  });
});
