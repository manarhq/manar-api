import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { failClosed } from '../../common/fail-closed/fail-closed';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { EnterpriseGateService } from '../common/enterprise-gate.service';
import { verifyDeviceSignature } from './device-signature';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface WatchDevice {
  tenantId: string;
  deviceId: string;
  personId: string | null;
  identityVerified: boolean;
  publicSlug: string;
}

export type WatchRequest = FastifyRequest & {
  rawBody?: Buffer;
  watch?: WatchDevice;
};

/**
 * Every /watch/v1 route except enrolment: the tenant must be in enterprise mode and the request
 * signed by an enrolled device's key over method, path, time and the exact body bytes (R11). Any
 * missing piece is 401; a store that cannot be read is 503. Never allows on error.
 */
@Injectable()
export class DeviceSignatureGuard implements CanActivate {
  constructor(
    private readonly gate: EnterpriseGateService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<WatchRequest>();
    const tenantId = String(req.headers['x-watch-tenant'] ?? '');
    const deviceId = String(req.headers['x-watch-device'] ?? '');
    if (!UUID.test(tenantId) || !UUID.test(deviceId))
      throw new UnauthorizedException();
    const ent = await this.gate.requireEnabled(tenantId);
    const device = await failClosed('watch-device-store', async () => {
      const db = await this.tenants.getClient(tenantId);
      return db.entDevice.findUnique({ where: { id: deviceId } });
    });
    if (!device) throw new UnauthorizedException();
    // GET has no body; any other method must carry the raw bytes it was signed over.
    const body = req.method === 'GET' ? '' : req.rawBody;
    if (body === undefined) throw new UnauthorizedException();
    const ok = verifyDeviceSignature({
      jwk: device.publicKeyJwk,
      method: req.method,
      path: req.url.split('?')[0]!,
      time: req.headers['x-watch-time'] as string | undefined,
      now: Date.now(),
      body,
      signature: req.headers['x-watch-sig'] as string | undefined,
    });
    if (!ok) throw new UnauthorizedException();
    req.watch = {
      tenantId,
      deviceId,
      personId: device.personId,
      identityVerified: device.identityVerified,
      publicSlug: ent.publicSlug,
    };
    return true;
  }
}
