import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';

/** What `HostAuthGuard` attaches to a `/host/v1/*` request, from the verified host certificate. */
export interface HostContext {
  hostId: string;
  tenantId: string;
  machineId: string;
  /** Keycloak subject of the person who enrolled the device; null for older or key-less hosts. */
  ownerSubject: string | null;
  /** PENDING until the owner approves it; REJECTED and REVOKED never reach a handler. */
  status: 'PENDING' | 'APPROVED';
}

/** `hostContext`, not `host`: Fastify already owns `request.host` (the Host header). */
export type RequestWithHost = FastifyRequest & { hostContext?: HostContext };

export const CurrentHost = createParamDecorator(
  (_data: unknown, context: ExecutionContext): HostContext => {
    const request = context.switchToHttp().getRequest<RequestWithHost>();
    if (!request.hostContext) {
      throw new Error(
        '@CurrentHost() used on a route with no host attached: is HostAuthGuard applied?',
      );
    }
    return request.hostContext;
  },
);

const HOST_IDENTIFIER = /^host:\/\/([^/]+)\/([A-Za-z0-9._-]{1,128})$/;

/** `host://<tenantSlug>/<machineId>` -> its parts; null for anything else. */
export function parseHostIdentifier(
  identifier: string,
): { tenantSlug: string; machineId: string } | null {
  const m = HOST_IDENTIFIER.exec(identifier);
  return m ? { tenantSlug: m[1]!, machineId: m[2]! } : null;
}
