import { Injectable } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import type { FastifyInstance } from 'fastify';
import { isAllowedReadPath, type ReadResult } from './assistant.tools';

/** What the reader needs from Fastify; `inject` runs the full request lifecycle in-process. */
export type InjectFn = (opts: {
  method: 'GET';
  url: string;
  headers: Record<string, string>;
}) => Promise<{ statusCode: number; body: string }>;

/**
 * Every tenant read the assistant makes goes through here: an in-process
 * `GET` on manar-api's own human HTTP routes, carrying the signed-in
 * user's own `Authorization` header and nothing else. The route's
 * JwtAuthGuard, RolesGuard and issuer-based tenant resolution therefore
 * decide what the assistant may see, exactly as they do for the console.
 * There is no service account and no other credential here to elevate to.
 */
@Injectable()
export class AssistantReader {
  private readonly inject: InjectFn;

  constructor(adapterHost: HttpAdapterHost) {
    this.inject = (opts) =>
      adapterHost.httpAdapter.getInstance<FastifyInstance>().inject(opts);
  }

  async get(path: string, authorization: string): Promise<ReadResult> {
    if (!isAllowedReadPath(path)) {
      throw new Error('assistant read path not allowed');
    }
    const res = await this.inject({
      method: 'GET',
      url: path,
      headers: { authorization, accept: 'application/json' },
    });
    if (res.statusCode < 200 || res.statusCode >= 300) {
      return { ok: false, status: res.statusCode };
    }
    try {
      return { ok: true, body: JSON.parse(res.body) as unknown };
    } catch {
      return { ok: false, status: 502 };
    }
  }
}
