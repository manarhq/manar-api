import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  Get,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController, ApiTags } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { HostAuthGuard } from '../host-mtls/host-auth.guard';
import { CurrentHost, type HostContext } from '../host-mtls/host-context';
import {
  SecretsConflictError,
  SecretsNotFoundError,
  SecretsService,
} from './secrets.service';
import {
  AccessRequestSchema,
  HostEventsBatchSchema,
  VaultReportSchema,
} from './secrets.validation';

function http(error: unknown): never {
  if (error instanceof SecretsNotFoundError)
    throw new NotFoundException(error.message);
  if (error instanceof SecretsConflictError)
    throw new ConflictException(error.message);
  throw error;
}

/** `/host/v1/events` and `/host/v1/secrets/*`: the device's side of the watcher and the vault (mTLS). */
@ApiTags('host')
@ApiExcludeController()
@Controller('host/v1')
@UseGuards(HostAuthGuard)
export class SecretsHostController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly secrets: SecretsService,
  ) {}

  /** Only an approved device may write: a pending one has not been accepted by its owner. */
  private async client(host: HostContext) {
    if (host.status !== 'APPROVED') {
      throw new ForbiddenException('This device is not approved yet');
    }
    return this.tenants.getClient(host.tenantId);
  }

  @Post('events')
  async events(@CurrentHost() host: HostContext, @Body() body: unknown) {
    const { events } = parseBodyOrThrow(HostEventsBatchSchema, body);
    return this.secrets.ingest(
      await this.client(host),
      host.tenantId,
      host.hostId,
      events,
    );
  }

  @Get('secrets/instructions')
  async instructions(@CurrentHost() host: HostContext) {
    return this.secrets.instructions(await this.client(host), host.hostId);
  }

  @Post('secrets/vault/report')
  async report(@CurrentHost() host: HostContext, @Body() body: unknown) {
    const b = parseBodyOrThrow(VaultReportSchema, body);
    return this.secrets
      .report(
        await this.client(host),
        host.tenantId,
        host.hostId,
        b.kind,
        b.ref,
        b.state,
        b.detail,
      )
      .catch(http);
  }

  @Post('secrets/access')
  async access(@CurrentHost() host: HostContext, @Body() body: unknown) {
    const b = parseBodyOrThrow(AccessRequestSchema, body);
    return this.secrets
      .createAccess(
        await this.client(host),
        host.hostId,
        b.kind,
        b.ref,
        b.program,
      )
      .catch(http);
  }

  @Get('secrets/access/:id')
  async accessStatus(
    @CurrentHost() host: HostContext,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    if (!id) throw new BadRequestException();
    return this.secrets
      .getAccess(await this.client(host), host.hostId, id)
      .catch(http);
  }
}
