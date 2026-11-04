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

/**
 * Authenticates `/host/v1/*` by the host certificate presented on the mTLS listener (:3443).
 * Node's TLS layer has already checked the chain; this resolves the certificate's SAN
 * `host://<tenantSlug>/<machineId>` to a Host in THAT tenant's database and requires that this
 * exact certificate serial was issued to that host and is not revoked. The tenant therefore comes
 * only from the verified certificate: a host of tenant A cannot name, reach or be mistaken for a
 * host of tenant B. Rejected and revoked hosts are refused; a PENDING host may call (it needs its
 * config to know when it is approved) and handlers see its status. A certificate issued to a host
 * the workspace removed gets 410 `device_removed` (revoked or not), so the device stops protecting
 * instead of retrying; nothing else returns that.
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
    if (!tenant || tenant.status !== 'ACTIVE') {
      this.logger.warn(`host request for an unknown or inactive tenant`);
      throw new UnauthorizedException('Unknown host');
    }
    let client;
    try {
      client = await this.tenants.getClient(tenant.id);
    } catch (error) {
      if (error instanceof TenantNotFoundError) {
        throw new UnauthorizedException('Unknown host');
      }
      throwFailClosed('tenant-db', error);
    }
    const serialNumber = normalizeSerialNumber(certificate.serialNumber);
    const [host, row] = await failClosed('tenant-db', () =>
      Promise.all([
        client.host.findUnique({ where: { machineId: parsed.machineId } }),
        client.hostCertificate.findUnique({
          where: { serialNumber },
          include: { host: { select: { status: true } } },
        }),
      ]),
    );
    // By the certificate, not the machineId: a machine removed long ago may have enrolled again
    // as a new host, and this certificate still belongs to the removed one.
    if (row?.host.status === 'REMOVED') {
      throw new GoneException({
        statusCode: 410,
        code: 'device_removed',
        message: 'This device was removed from the workspace',
      });
    }
    if (!host || (host.status !== 'PENDING' && host.status !== 'APPROVED')) {
      throw new UnauthorizedException('Host is not active');
    }
    if (!row || row.hostId !== host.id || row.revokedAt) {
      throw new UnauthorizedException(
        'Certificate is unknown or has been revoked',
      );
    }
    request.hostContext = {
      hostId: host.id,
      tenantId: tenant.id,
      machineId: host.machineId,
      ownerSubject: host.ownerSubject,
      status: host.status,
    };
    return true;
  }
}
