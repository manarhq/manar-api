import { Body, Controller, HttpCode, Post, UseGuards } from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { HostAuthGuard } from '../host-mtls/host-auth.guard';
import { CurrentHost, type HostContext } from '../host-mtls/host-context';
import {
  HostAuthorizeSchema,
  HostAuthorizeService,
} from './host-authorize.service';
import { HostToolsService, InventoryRequestSchema } from './host-tools.service';

/** Device routes of the coverage track, on the mTLS listener. */
@ApiExcludeController()
@Controller('host/v1')
@UseGuards(HostAuthGuard)
export class HostCoverageController {
  constructor(
    private readonly tools: HostToolsService,
    private readonly authorizer: HostAuthorizeService,
  ) {}

  @Post('inventory')
  @HttpCode(200)
  inventory(@CurrentHost() host: HostContext, @Body() body: unknown) {
    return this.tools.report(
      host,
      parseBodyOrThrow(InventoryRequestSchema, body),
    );
  }

  @Post('authorize')
  @HttpCode(200)
  authorize(@CurrentHost() host: HostContext, @Body() body: unknown) {
    return this.authorizer.authorize(
      host,
      parseBodyOrThrow(HostAuthorizeSchema, body),
    );
  }
}
