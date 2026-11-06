import type { TLSSocket } from 'node:tls';
import {
  CanActivate,
  ExecutionContext,
  GoneException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as x509 from '@peculiar/x509';
import { normalizeSerialNumber } from '../agents/serial-number.util';
import { failClosed, throwFailClosed } from '../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TenantNotFoundError } from '../database/tenant-database.errors';
import { parseHostIdentifier, type RequestWithHost } from './host-context';
import { hostRefused } from './host-refusal';

const removed = () =>
  new GoneException({
    statusCode: 410,
    code: 'device_removed',
    message: 'This device was removed from the workspace',
  });

/**
 * Authenticates `/host/v1/*` by the host certificate presented on the mTLS listener (:3443).
 * Node's TLS layer has already checked the chain; this resolves the certificate's SAN
 * `host://<tenantSlug>/<machineId>` to a Host in THAT tenant's database and requires that this
 * exact certificate serial was issued to that host and is not revoked. The tenant therefore comes
 * only from the verified certificate: a host of tenant A cannot name, reach or be mistaken for a
 * host of tenant B. A PENDING host may call (it needs its config to know when it is approved) and
 * handlers see its status. A certificate issued to a host the workspace removed, or of a personal
 * workspace deleted with its owner's account, gets 410 `device_removed` (revoked or not), so the
 * device stops protecting; nothing else returns that. Every other refusal of a genuine device
 * certificate is 423 (host-refusal.ts): the device keeps protecting. 401 is only for a caller that
 * is not one of our devices at all.
 */
@Injectable()
export class HostAuthGuard implements CanActivate {
  private readonly logger = new Logger(HostAuthGuard.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithHost>();
    const socket = request.raw.socket as TLSSocket;
    if (!socket.authorized) {
      throw new UnauthorizedException('Client certificate is not authorized');
    }
    const der = socket.getPeerCertificate(false)?.raw;
    if (!der) {
      throw new UnauthorizedException('No client certificate was presented');
    }
    let certificate: x509.X509Certificate;
    try {
      certificate = new x509.X509Certificate(der);
    } catch {
      throw new UnauthorizedException('Client certificate could not be parsed');
    }
    const identifier = certificate
      .getExtension(x509.SubjectAlternativeNameExtension)
      ?.names.items.find((n) => n.type === 'url')?.value;
    const parsed = identifier ? parseHostIdentifier(identifier) : null;
    if (!parsed) {
      throw new UnauthorizedException(
        'Client certificate is not a host certificate',
      );
    }

    const tenant = await failClosed('control-db', () =>
      this.control.tenant.findUnique({ where: { slug: parsed.tenantSlug } }),
    );
    if (!tenant) {
      // A personal workspace deleted with its owner's account: its devices give the tools back.
      const gone = await failClosed('control-db', () =>
        this.control.deletedWorkspace.findUnique({
          where: { slug: parsed.tenantSlug },
        }),
      );
      if (gone?.reason === 'account_deleted') throw removed();
      throw hostRefused('workspace_deleted', 'This workspace no longer exists');
    }
    if (tenant.status === 'SUSPENDED') {
      throw hostRefused('account_suspended', 'This workspace is suspended');
    }
    if (tenant.status !== 'ACTIVE') {
      this.logger.warn(`host request for an inactive tenant`);
      throw hostRefused('workspace_deleted', 'This workspace is not active');
    }
    let client;
    try {
      client = await this.tenants.getClient(tenant.id);
    } catch (error) {
      if (error instanceof TenantNotFoundError) {
        throw hostRefused('workspace_deleted', 'This workspace is not active');
      }
      throwFailClosed('tenant-db', error);
    }
    const serialNumber = normalizeSerialNumber(certificate.serialNumber);
    // The certificate row names the host: several hosts may share a machineId (a clone or a
    // re-install waits as its own device), and a machine removed long ago may have enrolled again
    // as a new host while this certificate still belongs to the removed one.
    const row = await failClosed('tenant-db', () =>
      client.hostCertificate.findUnique({
        where: { serialNumber },
        include: { host: true },
      }),
    );
    const host = row?.host;
    if (host?.status === 'REMOVED') throw removed();
    if (!row || !host || row.revokedAt || host.machineId !== parsed.machineId) {
      throw hostRefused(
        'certificate_revoked',
        'Certificate is unknown or has been revoked',
      );
    }
    if (host.status !== 'PENDING' && host.status !== 'APPROVED') {
      throw hostRefused('device_revoked', 'This device was revoked');
    }
    request.hostContext = {
      hostId: host.id,
      tenantId: tenant.id,
      machineId: host.machineId,
      ownerSubject: host.ownerSubject,
      status: host.status,
      agentVersion: host.agentVersion,
      agentOs: host.agentOs,
      agentArch: host.agentArch,
    };
    return true;
  }
}
