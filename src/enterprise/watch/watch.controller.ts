import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import type { FastifyReply } from 'fastify';
import { failClosed } from '../../common/fail-closed/fail-closed';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import {
  DeviceSignatureGuard,
  type WatchRequest,
} from './device-signature.guard';
import { PolicyCompilerService } from './policy-compiler.service';
import { WatchDeviceService } from './watch-device.service';
import {
  EnrolSchema,
  EventsSchema,
  HeartbeatSchema,
  IdentitySchema,
  NonceSchema,
  PolicyQuerySchema,
} from './watch.validation';
import { parseOr400 } from '../common/parse';

const POLL_STEP_MS = 2000;

/**
 * The WATCH browser extension's API (spec 6.1). No cookies, no JWT: enrolment presents the
 * tenant's enrolment key, everything else is signed by the device key (DeviceSignatureGuard).
 * Kept out of the public OpenAPI document; the extension is its only client.
 */
@ApiExcludeController()
@Controller('watch/v1')
export class WatchController {
  constructor(
    private readonly devices: WatchDeviceService,
    private readonly compiler: PolicyCompilerService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  @Post('enrol')
  @HttpCode(201)
  enrol(@Body() body: unknown) {
    return this.devices.enrol(parseOr400(EnrolSchema, body));
  }

  /**
   * Long-poll: answers at once when the device's policy differs from `since`, otherwise holds up
   * to `wait` seconds and answers 204. ponytail: re-compiles every 2 s while holding; move to a
   * change notification (Redis pub/sub) when tenants have thousands of open browsers.
   */
  @Get('policy')
  @UseGuards(DeviceSignatureGuard)
  async policy(
    @Req() req: WatchRequest,
    @Query() query: unknown,
    @Res() res: FastifyReply,
  ) {
    const { since, wait } = parseOr400(PolicyQuerySchema, query);
    const d = req.watch!;
    const compile = () =>
      failClosed('watch-policy', async () =>
        this.compiler.forDevice(
          await this.tenants.getClient(d.tenantId),
          d.tenantId,
          d.publicSlug,
          d.personId,
        ),
      );
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const p = await compile();
      if (p.version !== since) return res.status(200).send(p);
      if (Date.now() + POLL_STEP_MS > deadline) return res.status(204).send();
      await new Promise((r) => setTimeout(r, POLL_STEP_MS));
    }
  }

  @Post('heartbeat')
  @HttpCode(204)
  @UseGuards(DeviceSignatureGuard)
  async heartbeat(@Req() req: WatchRequest, @Body() body: unknown) {
    await this.devices.heartbeat(req.watch!, parseOr400(HeartbeatSchema, body));
  }

  @Post('events')
  @HttpCode(204)
  @UseGuards(DeviceSignatureGuard)
  async events(@Req() req: WatchRequest, @Body() body: unknown) {
    await this.devices.events(req.watch!, parseOr400(EventsSchema, body));
  }

  @Post('identity/nonce')
  @UseGuards(DeviceSignatureGuard)
  nonce(@Req() req: WatchRequest, @Body() body: unknown) {
    return this.devices.identityNonce(
      req.watch!,
      parseOr400(NonceSchema, body).redirectUri,
    );
  }

  @Post('identity')
  @HttpCode(200)
  @UseGuards(DeviceSignatureGuard)
  identity(@Req() req: WatchRequest, @Body() body: unknown) {
    return this.devices.verifyIdentity(
      req.watch!,
      parseOr400(IdentitySchema, body).idToken,
    );
  }
}
