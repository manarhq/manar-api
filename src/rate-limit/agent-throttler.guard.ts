import type { TLSSocket } from 'node:tls';
import { Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  InjectThrottlerOptions,
  InjectThrottlerStorage,
  ThrottlerGuard,
} from '@nestjs/throttler';
import type {
  ThrottlerModuleOptions,
  ThrottlerStorage,
} from '@nestjs/throttler';
import * as x509 from '@peculiar/x509';
import type { RequestWithAgentContext } from '../agent-mtls/agent-context';

/**
 * Phase 12a: rate-limits the mTLS `/agent/v1/*` surface **per agent**, not
 * per caller IP -- many agents can legitimately share an egress IP (a
 * shared subnet, a NAT gateway, a proxy), and a bucket keyed by IP would
 * let one misbehaving agent exhaust every other agent's budget behind the
 * same address. Keyed by agent instead, this guard's whole point (a single
 * bad actor never exhausting a limit shared with every other agent) holds
 * regardless of network topology.
 *
 * Registered globally (`APP_GUARD`, `AgentMtlsAppModule`), so it runs
 * *before* `AgentMtlsGuard` -- `request.agentContext` isn't populated yet.
 * Rather than duplicate `AgentMtlsGuard`'s full identity resolution (which
 * hits the control + tenant databases to confirm the agent is `ACTIVE` and
 * its certificate isn't individually revoked -- work this guard has no
 * need to repeat just to pick a rate-limit bucket), this reads the same
 * client certificate's Subject Alternative Name identifier
 * (`agent://<tenantSlug>/<slug>`) directly off the already-TLS-verified
 * socket (`rejectUnauthorized: true` on this listener already refused any
 * connection without a certificate chaining to the trusted CA before this
 * guard ever runs -- see `src/main.ts`) and uses that raw string as the
 * tracker. This is a partition key, not an identity trust decision: an
 * unrecognized/inactive agent's requests still land in *some* bucket here,
 * then get correctly rejected by `AgentMtlsGuard` immediately afterward.
 * Falls back to the connection's IP for the (structurally rare, given
 * `rejectUnauthorized: true`) case of no parseable certificate at all.
 */
@Injectable()
export class AgentThrottlerGuard extends ThrottlerGuard {
  constructor(
    @InjectThrottlerOptions() options: ThrottlerModuleOptions,
    @InjectThrottlerStorage() storage: ThrottlerStorage,
    reflector: Reflector,
  ) {
    super(options, storage, reflector);
  }

  protected override getTracker(req: RequestWithAgentContext): Promise<string> {
    if (req.agentContext?.agent?.id) {
      return Promise.resolve(`agent:${req.agentContext.agent.id}`);
    }

    const identifier = readCertificateIdentifier(req);
    if (identifier) {
      return Promise.resolve(`agent-cert:${identifier}`);
    }

    return Promise.resolve(`ip:${req.ip}`);
  }
}

function readCertificateIdentifier(
  req: RequestWithAgentContext,
): string | null {
  try {
    const socket = req.raw.socket as TLSSocket;
    const peerCertificateDer = socket.getPeerCertificate?.(false)?.raw;
    if (!peerCertificateDer) return null;

    const certificate = new x509.X509Certificate(peerCertificateDer);
    const sanExtension = certificate.getExtension(
      x509.SubjectAlternativeNameExtension,
    );
    const identifier = sanExtension?.names.items.find(
      (name) => name.type === 'url',
    )?.value;
    return identifier ?? null;
  } catch {
    return null;
  }
}
