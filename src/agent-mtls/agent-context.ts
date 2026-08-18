import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';

/**
 * The trustworthy identity `AgentMtlsGuard` attaches to a request on
 * successful mTLS verification + local status/revocation checks — the
 * agent-facing analogue of `AuthContext` (`src/auth/auth-context.ts`).
 */
export interface AgentContext {
  tenant: {
    id: string;
    slug: string;
  };
  agent: {
    id: string;
    slug: string;
    identifier: string;
  };
  certificate: {
    /** Canonical form: uppercase hex, no separators — see serial-number.util.ts. */
    serialNumber: string;
  };
}

/** The property `AgentMtlsGuard` attaches `AgentContext` to on the request. */
export type RequestWithAgentContext = FastifyRequest & {
  agentContext?: AgentContext;
};

/**
 * Controller-facing accessor for `AgentContext`, mirroring `@CurrentAuth()`.
 * Throws if used on a route not guarded by `AgentMtlsGuard`.
 */
export const CurrentAgent = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AgentContext => {
    const request = context
      .switchToHttp()
      .getRequest<RequestWithAgentContext>();
    if (!request.agentContext) {
      throw new Error(
        '@CurrentAgent() used on a route with no AgentContext attached — is AgentMtlsGuard applied to this route?',
      );
    }
    return request.agentContext;
  },
);
