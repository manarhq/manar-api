import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import {
  HTTP_SERVER_OPTIONS,
  PROXY_IDLE_TIMEOUT_MS,
} from './http-server-options';

describe('HTTP server keep-alive', () => {
  it('outlives the proxy idle timeout, so the proxy always closes an idle socket first', async () => {
    const app = Fastify(HTTP_SERVER_OPTIONS);
    await app.ready();
    expect(app.server.keepAliveTimeout).toBeGreaterThan(PROXY_IDLE_TIMEOUT_MS);
    await app.close();
  });
});
