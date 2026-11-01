import {
  Body,
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
import { parseBodyOrThrow } from '../../agents/parse-body.util';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { CurrentHost, type HostContext } from '../../host-mtls/host-context';
import { HostAuthGuard } from '../../host-mtls/host-auth.guard';
import {
  FileChangesService,
  FileChangeNotFoundError,
} from './file-changes.service';
import {
  FileChangeBatchSchema,
  RestoreResultSchema,
} from './file-changes.validation';

/** Undo AI file changes, device side (mTLS). Only an approved device may report or restore. */
@ApiTags('host')
@ApiExcludeController()
@Controller('host/v1/undo')
@UseGuards(HostAuthGuard)
export class HostChangesController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly changes: FileChangesService,
  ) {}

  private approved(host: HostContext) {
    if (host.status !== 'APPROVED')
      throw new ForbiddenException('Device is not approved');
  }

  @Post('changes')
  async report(@CurrentHost() host: HostContext, @Body() body: unknown) {
    this.approved(host);
    const batch = parseBodyOrThrow(FileChangeBatchSchema, body);
    const client = await this.tenants.getClient(host.tenantId);
    return this.changes.report(client, host.hostId, batch);
  }

  @Get('restores')
  async pending(@CurrentHost() host: HostContext) {
    this.approved(host);
    const client = await this.tenants.getClient(host.tenantId);
    return { items: await this.changes.pendingRestores(client, host.hostId) };
  }

  @Post('restores/:id/result')
  async result(
    @CurrentHost() host: HostContext,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ) {
    this.approved(host);
    const result = parseBodyOrThrow(RestoreResultSchema, body);
    const client = await this.tenants.getClient(host.tenantId);
    try {
      await this.changes.restoreResult(
        client,
        host.tenantId,
        host.hostId,
        id,
        result,
      );
    } catch (e) {
      if (e instanceof FileChangeNotFoundError) throw new NotFoundException();
      throw e;
    }
    return { ok: true };
  }
}
