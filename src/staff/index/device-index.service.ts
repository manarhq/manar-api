import { createHash } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ControlPrismaService } from '../../database/control-prisma.service';

/** The device id shared with the launch offer's anti-farming check (src/growth/launch-offer). */
export const deviceHashOf = (machineId: string) =>
  createHash('sha256').update(`manar-launch-device:${machineId}`).digest('hex');

export interface IndexedHost {
  hostId: string;
  machineId: string;
  hostname?: string | null;
  os?: string | null;
  status: string;
  ownerSubject?: string | null;
  ekHash?: string | null;
  lastSeenAt?: Date | null;
}

/**
 * Hosted devices across every workspace, for staff search (DESK spec §7.4, §17.1). Written when a
 * device registers and by `pnpm manar devices:index`; status and last-seen on record pages are read
 * live from the workspace, so this index only needs to find a device. Never throws into the caller.
 */
@Injectable()
export class DeviceIndexService {
  private readonly logger = new Logger(DeviceIndexService.name);
  constructor(private readonly control: ControlPrismaService) {}

  async upsert(tenantId: string, h: IndexedHost): Promise<void> {
    const data = {
      machineId: h.machineId,
      deviceHash: deviceHashOf(h.machineId),
      ekHash: h.ekHash ?? null,
      hostname: h.hostname ?? null,
      os: h.os ?? null,
      status: h.status,
      ownerSubject: h.ownerSubject ?? null,
      lastSeenAt: h.lastSeenAt ?? null,
    };
    await this.control.staffDeviceIndex
      .upsert({
        where: { tenantId_hostId: { tenantId, hostId: h.hostId } },
        create: { tenantId, hostId: h.hostId, ...data },
        update: data,
      })
      .catch((e: unknown) =>
        this.logger.warn(`device index not updated: ${String(e)}`),
      );
  }
}
