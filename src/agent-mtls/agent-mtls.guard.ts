import type { TLSSocket } from 'node:tls';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import { parseAgentIdentifier } from '../agents/agent-identifier';
import { normalizeSerialNumber } from '../agents/serial-number.util';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TenantNotFoundError } from '../database/tenant-database.errors';
import { failClosed, throwFailClosed } from '../common/fail-closed/fail-closed';
import { AgentContext, RequestWithAgentContext } from './agent-context';

/**
 * Resolves an mTLS request's verified client certificate back to an
 * `Agent` + `AgentCertificate` row, and rejects unless the agent is
 * `ACTIVE` *and* this specific certificate serial isn't individually
 * revoked. This is defense in depth *beyond* Node's own TLS chain
 * validation (`requestCert: true, rejectUnauthorized: true` on the
 * `https` listener in `src/main.ts` already refuses the TLS handshake
 * itself for a certificate that doesn't chain to the trusted intermediate
 * CA — a request with no valid client certificate never reaches this guard
 * at all): a certificate can be individually revoked before its
 * `notAfter`, and nothing at the TLS layer consults that per-request
 * (Section 71's mandatory immediate-revocation invariant — verified by an
 * actual provision → use → revoke → retry-must-fail test, not assumed).
 *
 * There is no JWT/issuer on this surface to carry tenant identity the way
 * `JwtAuthGuard` has one — instead, the certificate's own Subject
 * Alternative Name (`agent://<tenantSlug>/<slug>`, the exact identifier
 * `CertificateAuthorityService` validated before ever signing it) is
 * parsed to resolve which tenant's isolated database to look the agent up
 * in, mirroring how `JwtAuthGuard` resolves tenant identity from a
 * verified token's issuer rather than any client-supplied value.
 */
@Injectable()
export class AgentMtlsGuard implements CanActivate {
  private readonly logger = new Logger(AgentMtlsGuard.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<RequestWithAgentContext>();
    const socket = request.raw.socket as TLSSocket;

    // Belt-and-suspenders: with `rejectUnauthorized: true` on the listener,
    // an unauthorized connection is already refused at the TLS handshake
    // and never reaches here — this check exists for the same reason
    // AgentMtlsGuard exists at all: never assume a lower layer's
    // enforcement without checking it.
    if (!socket.authorized) {
      throw new UnauthorizedException('Client certificate is not authorized');
    }

    const peerCertificateDer = socket.getPeerCertificate(false)?.raw;
    if (!peerCertificateDer) {
      throw new UnauthorizedException('No client certificate was presented');
    }

    let certificate: x509.X509Certificate;
    try {
      certificate = new x509.X509Certificate(peerCertificateDer);
    } catch {
      throw new UnauthorizedException('Client certificate could not be parsed');
    }

    const sanExtension = certificate.getExtension(
      x509.SubjectAlternativeNameExtension,
    );
    const identifier = sanExtension?.names.items.find(
      (name) => name.type === 'url',
    )?.value;
    if (!identifier) {
      throw new UnauthorizedException(
        'Client certificate has no agent identifier Subject Alternative Name',
      );
    }

    const parsedIdentifier = parseAgentIdentifier(identifier);
    if (!parsedIdentifier) {
      throw new UnauthorizedException(
        'Client certificate has a malformed agent identifier',
      );
    }

    const tenant = await failClosed('control-db', () =>
      this.control.tenant.findUnique({
        where: { slug: parsedIdentifier.tenantSlug },
      }),
    );
    if (!tenant) {
      this.logger.warn(
        `mTLS request for unknown tenant slug "${parsedIdentifier.tenantSlug}"`,
      );
      throw new UnauthorizedException('Unknown agent');
    }
    // A suspended or deleted tenant's agents stop at once, even while a tenant DB client is
    // still cached for it (platform API suspend, ADR-0010).
    if (tenant.status !== 'ACTIVE') {
      this.logger.warn(
        `mTLS request for tenant "${parsedIdentifier.tenantSlug}" in status ${tenant.status}`,
      );
      throw new UnauthorizedException('Unknown agent');
    }

    const tenantClient = await this.resolveTenantClientOrUnauthorized(
      tenant.id,
    );

    const agent = await failClosed('tenant-db', () =>
      tenantClient.agent.findUnique({ where: { identifier } }),
    );
    if (!agent || agent.status !== 'ACTIVE') {
      throw new UnauthorizedException('Agent is not active');
    }

    const serialNumber = normalizeSerialNumber(certificate.serialNumber);
    const certificateRow = await failClosed('tenant-db', () =>
      tenantClient.agentCertificate.findUnique({ where: { serialNumber } }),
    );
    if (
      !certificateRow ||
      certificateRow.agentId !== agent.id ||
      certificateRow.revokedAt
    ) {
      throw new UnauthorizedException(
        'Certificate is unknown or has been revoked',
      );
    }

    const agentContext: AgentContext = {
      tenant: { id: tenant.id, slug: tenant.slug },
      agent: { id: agent.id, slug: agent.slug, identifier: agent.identifier },
      certificate: { serialNumber },
    };
    request.agentContext = agentContext;

    return true;
  }

  private async resolveTenantClientOrUnauthorized(tenantId: string) {
    try {
      return await this.tenantDatabaseManager.getClient(tenantId);
    } catch (error) {
      if (error instanceof TenantNotFoundError) {
        throw new UnauthorizedException('Unknown agent');
      }
      throwFailClosed('tenant-db', error);
    }
  }
}
