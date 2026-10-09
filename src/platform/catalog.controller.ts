import {
  Body,
  Controller,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
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
import { CatalogService } from './catalog.service';
import {
  CATALOG_FEATURES,
  CatalogPatchSchema,
  LLM_PROVIDERS,
} from './catalog.validation';

class CatalogFeaturesDto {
  @ApiProperty() assistant!: boolean;
  @ApiProperty() watcher!: boolean;
  @ApiProperty() packs!: boolean;
  @ApiProperty() llm_proxy!: boolean;
}

class CatalogPackDto {
  @ApiProperty({ example: 'it-helpdesk' }) id!: string;
  @ApiProperty() version!: number;
  @ApiProperty() enabled!: boolean;
  @ApiProperty({
    type: [String],
    description:
      'Agent ids bound to this pack: all their tasks are this pack. Omitted on PATCH keeps them.',
  })
  agents!: string[];
}

class CatalogAgentDto {
  @ApiProperty() id!: string;
  @ApiProperty() slug!: string;
  @ApiProperty() displayName!: string;
  @ApiProperty() status!: string;
}

class CatalogModelDto {
  @ApiProperty({ enum: LLM_PROVIDERS }) provider!: string;
  @ApiProperty() model!: string;
  @ApiProperty() uaeResidency!: boolean;
  @ApiProperty({ type: Number, nullable: true })
  monthlyTokenQuota!: number | null;
}

class CatalogPatchDto {
  @ApiPropertyOptional({
    description: `Partial; keys: ${CATALOG_FEATURES.join(', ')}`,
  })
  features?: Partial<CatalogFeaturesDto>;
  @ApiPropertyOptional({ type: [CatalogPackDto] }) packs?: CatalogPackDto[];
  @ApiPropertyOptional({ type: CatalogModelDto, nullable: true })
  model?: CatalogModelDto | null;
}

class CatalogConnectorDto {
  @ApiProperty() name!: string;
  @ApiProperty() type!: string;
  @ApiProperty({ type: String, nullable: true }) vendor!: string | null;
  @ApiProperty({ enum: ['HTTP', 'MCP', 'MICROSOFT', 'GITLAB'] })
  protocol!: string;
  @ApiProperty() enabled!: boolean;
}

class CatalogViewDto {
  @ApiProperty() tenantId!: string;
  @ApiProperty({
    description: 'False until staff set anything (defaults apply)',
  })
  managed!: boolean;
  @ApiProperty({ type: CatalogFeaturesDto }) features!: CatalogFeaturesDto;
  @ApiProperty({ type: [CatalogPackDto] }) packs!: CatalogPackDto[];
  @ApiProperty({ type: CatalogModelDto, nullable: true })
  model!: CatalogModelDto | null;
  @ApiProperty({ type: String, nullable: true }) updatedBy!: string | null;
  @ApiProperty({ type: Date, nullable: true }) updatedAt!: Date | null;
  @ApiProperty({
    description: 'Model tokens this calendar month (UTC); null if unreadable',
  })
  usage!: { month: string; tokens: number | null };
  @ApiProperty({
    type: [CatalogConnectorDto],
    nullable: true,
    description: 'Registered tools; null unless the tenant is ACTIVE',
  })
  connectors!: CatalogConnectorDto[] | null;
  @ApiProperty({
    type: [CatalogAgentDto],
    nullable: true,
    description:
      'Agents, for binding them to a pack; null unless the tenant is ACTIVE',
  })
  agents!: CatalogAgentDto[] | null;
}

/**
 * Per-tenant catalog for manar-fleet: feature flags, enabled packs, the LLM route, this month's
 * token use and the registered connectors. Same service-to-service guard as the platform API
 * (ADR-0010). Staff's two-person rule runs in manar-fleet before it calls here.
 */
@ApiTags('platform')
@ApiBearerAuth('platform')
@UseGuards(PlatformAuthGuard)
@Controller('platform/v1/tenants/:id/catalog')
export class CatalogController {
  constructor(private readonly service: CatalogService) {}

  @Get()
  @ApiOperation({
    summary: 'Feature flags, packs, LLM route, usage, connectors',
  })
  @ApiResponse({ status: 200, type: CatalogViewDto })
  get(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.view(id);
  }

  @Patch()
  @ApiOperation({
    summary:
      'Merge flags, upsert packs by id, replace the model (null = default)',
  })
  @ApiResponse({ status: 200, type: CatalogViewDto })
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: CatalogPatchDto,
    @Req() req: RequestWithPlatformCaller,
  ) {
    return this.service.update(
      id,
      parseBodyOrThrow(CatalogPatchSchema, body),
      req.platformCaller?.clientId ?? 'unknown',
    );
  }
}
