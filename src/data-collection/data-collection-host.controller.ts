import {
  Body,
  Controller,
  HttpCode,
  PayloadTooLargeException,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController, ApiTags } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { HostAuthGuard } from '../host-mtls/host-auth.guard';
import { CurrentHost, type HostContext } from '../host-mtls/host-context';
import { DataCollectionService } from './data-collection.service';
import {
  DeviceTelemetryBody,
  MAX_DEVICE_BODY_BYTES,
} from './data-collection.dto';

/** `POST /host/v1/telemetry`: the device's daily batch (mTLS). */
@ApiTags('host')
@ApiExcludeController()
@Controller('host/v1')
@UseGuards(HostAuthGuard)
export class DataCollectionHostController {
  constructor(private readonly data: DataCollectionService) {}

  @Post('telemetry')
  @HttpCode(204)
  async telemetry(@CurrentHost() host: HostContext, @Body() body: unknown) {
    if (Buffer.byteLength(JSON.stringify(body ?? null)) > MAX_DEVICE_BODY_BYTES)
      throw new PayloadTooLargeException();
    const batch = parseBodyOrThrow(DeviceTelemetryBody, body);
    // A device its owner has not approved sends nothing worth keeping.
    if (host.status !== 'APPROVED') return;
    await this.data.ingestDevice(host.tenantId, host.ownerSubject, batch);
  }
}
