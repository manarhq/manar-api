import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiProperty,
  ApiPropertyOptional,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  PlatformAuthGuard,
  type RequestWithPlatformCaller,
} from './platform-auth.guard';
import { PlatformService } from './platform.service';
import { CreatePlatformTenantSchema } from './platform.validation';

class CreatePlatformTenantDto {
  @ApiProperty({ example: 'acme-soc' }) slug!: string;
  @ApiProperty() name!: string;
  @ApiPropertyOptional({ enum: ['UAE', 'CUSTOM_REGION', 'AIR_GAPPED'] })
  residency?: string;
}

class PlatformTenantDto {
  @ApiProperty() id!: string;
  @ApiProperty() slug!: string;
  @ApiProperty() name!: string;
  @ApiProperty({
    enum: ['PROVISIONING', 'ACTIVE', 'SUSPENDED', 'DEPROVISIONING', 'DELETED'],
  })
  status!: string;
  @ApiProperty() residency!: string;
  @ApiProperty() createdAt!: Date;
}

class PlatformTenantSummaryDto extends PlatformTenantDto {
  @ApiPropertyOptional({
    description: 'TENANT_OWNER and SECURITY_ADMIN users; ACTIVE tenants only',
  })
  admins?: { displayName: string; email: string; roles: string[] }[];
  @ApiPropertyOptional() tools?: {
    name: string;
    vendor: string | null;
    enabled: boolean;
  }[];
  @ApiPropertyOptional() agents?: { total: number; active: number };
  @ApiPropertyOptional() usage?: {
    windowDays: number;
    tasks: number;
    toolInvocations: number;
    approvalRequests: number;
  };
}

const caller = (req: RequestWithPlatformCaller) =>
  req.platformCaller?.clientId ?? 'unknown';

/**
 * Platform-level tenant lifecycle for manar-fleet (ADR-0010). Service-to-service only: a
 * client-credentials token from the platform realm with PLATFORM_API_ROLE. No tenant JWT is
 * accepted here, and tenant routes never accept this token.
 */
@ApiTags('platform')
@ApiBearerAuth('platform')
@UseGuards(PlatformAuthGuard)
@Controller('platform/v1/tenants')
export class PlatformController {
  constructor(private readonly service: PlatformService) {}

  @Get()
  @ApiOperation({ summary: 'List tenants (control-plane fields only)' })
  @ApiResponse({ status: 200, type: [PlatformTenantDto] })
  list() {
    return this.service.list();
  }

  @Post()
  @ApiOperation({ summary: 'Provision a tenant: database and Keycloak realm' })
  @ApiResponse({ status: 201, type: PlatformTenantDto })
  create(
    @Body() body: CreatePlatformTenantDto,
    @Req() req: RequestWithPlatformCaller,
  ) {
    return this.service.create(
      parseBodyOrThrow(CreatePlatformTenantSchema, body),
      caller(req),
    );
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Tenant summary: admins, tools, agent counts, 30-day usage',
  })
  @ApiResponse({ status: 200, type: PlatformTenantSummaryDto })
  summary(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.summary(id);
  }

  @Post(':id/suspend')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Suspend: humans and agents of this tenant are refused',
  })
  @ApiResponse({ status: 200, type: PlatformTenantDto })
  suspend(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: RequestWithPlatformCaller,
  ) {
    return this.service.suspend(id, caller(req));
  }

  @Post(':id/resume')
  @HttpCode(200)
  @ApiOperation({ summary: 'Resume a suspended tenant' })
  @ApiResponse({ status: 200, type: PlatformTenantDto })
  resume(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: RequestWithPlatformCaller,
  ) {
    return this.service.resume(id, caller(req));
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Mark the tenant DELETED (database and realm are kept)',
  })
  @ApiResponse({ status: 200, type: PlatformTenantDto })
  remove(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: RequestWithPlatformCaller,
  ) {
    return this.service.remove(id, caller(req));
  }
}
