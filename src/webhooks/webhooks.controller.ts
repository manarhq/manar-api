import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { UnsafeOutboundUrlError } from '../common/ssrf/url-safety';
import { IdempotencyInterceptor } from '../idempotency/idempotency.interceptor';
import { WebhookRegistryService } from './webhook-registry.service';
import { WebhookEndpointNotFoundError } from './webhooks.errors';
import {
  CreateWebhookEndpointRequestSchema,
  UpdateWebhookEndpointRequestSchema,
} from './webhooks.validation';
import {
  CreateWebhookEndpointRequestDto,
  UpdateWebhookEndpointRequestDto,
  WebhookDeliveryResponseDto,
  WebhookEndpointCreatedResponseDto,
  WebhookEndpointListResponseDto,
  WebhookEndpointResponseDto,
} from './webhooks.dto';

/**
 * Phase 12a (Webhooks, Section 51) admin CRUD — `JwtAuthGuard`+`RolesGuard`
 * gated to `SECURITY_ADMIN`/`TENANT_OWNER`, the same role-gating convention
 * `KillSwitchesController` just established (see that controller's own doc
 * comment) and this codebase's general "a role capable of managing
 * security-relevant configuration" bar.
 */
@ApiTags('webhooks')
@ApiBearerAuth('jwt')
@Controller('webhooks')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
export class WebhooksController {
  constructor(
    private readonly webhookRegistryService: WebhookRegistryService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post()
  @UseInterceptors(IdempotencyInterceptor)
  @ApiOperation({
    summary: 'Register a webhook endpoint',
    description:
      'Generates a new HMAC signing secret and returns it in plaintext exactly once. The outbound URL is rejected if it resolves to a private/loopback/link-local/metadata-service address (SSRF protection). Supports an `Idempotency-Key` header — a replay with the same key returns the original response (and secret) rather than rotating it.',
  })
  @ApiBody({ type: CreateWebhookEndpointRequestDto })
  @ApiResponse({ status: 201, type: WebhookEndpointCreatedResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  async create(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<WebhookEndpointCreatedResponseDto> {
    const input = parseBodyOrThrow(CreateWebhookEndpointRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const { endpoint, secret } = await mapWebhookErrors(() =>
      this.webhookRegistryService.create(tenantClient, {
        ...input,
        createdBy: auth.user.id,
      }),
    );
    return { ...endpoint, secret };
  }

  @Get()
  @ApiOperation({
    summary: 'List registered webhook endpoints',
    description:
      'Cursor-paginated, newest first (Phase 11b Part 1 — see src/common/pagination/cursor-pagination.ts). Optional `enabled` filter. Note: this response envelope changed from a bare array to `{ items, nextCursor }` in Phase 11b Part 1, matching every other list endpoint added that phase.',
  })
  @ApiQuery({ name: 'enabled', required: false, type: Boolean })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Max 100, default 20.',
  })
  @ApiQuery({
    name: 'cursor',
    required: false,
    description: 'Opaque `nextCursor` from a previous page.',
  })
  @ApiResponse({ status: 200, type: WebhookEndpointListResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('enabled') enabled?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<WebhookEndpointListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.webhookRegistryService.list(tenantClient, {
      enabled:
        enabled === undefined
          ? undefined
          : enabled === 'true' || enabled === '1',
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a webhook endpoint' })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiResponse({ status: 200, type: WebhookEndpointResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async get(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<WebhookEndpointResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapWebhookErrors(() =>
      this.webhookRegistryService.get(tenantClient, id),
    );
  }

  @Patch(':id')
  @ApiOperation({
    summary: 'Update a webhook endpoint',
    description:
      'Partial update — only the provided fields change. Changing `url` re-runs the SSRF check.',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ type: UpdateWebhookEndpointRequestDto })
  @ApiResponse({ status: 200, type: WebhookEndpointResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async update(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<WebhookEndpointResponseDto> {
    const input = parseBodyOrThrow(UpdateWebhookEndpointRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapWebhookErrors(() =>
      this.webhookRegistryService.update(tenantClient, id, input),
    );
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Delete a webhook endpoint and its delivery history',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async remove(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<{ status: 'DELETED' }> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    await mapWebhookErrors(() =>
      this.webhookRegistryService.delete(tenantClient, id),
    );
    return { status: 'DELETED' };
  }

  @Get(':id/deliveries')
  @ApiOperation({ summary: "List a webhook endpoint's delivery history" })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiResponse({ status: 200, type: [WebhookDeliveryResponseDto] })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async listDeliveries(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<WebhookDeliveryResponseDto[]> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapWebhookErrors(() =>
      this.webhookRegistryService.listDeliveries(tenantClient, id),
    );
  }
}

/** Translates this module's typed domain errors into HTTP responses, mirroring `AgentsController`'s identical `mapAgentNotFound` helper. */
async function mapWebhookErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof WebhookEndpointNotFoundError) {
      throw new NotFoundException(error.message);
    }
    if (error instanceof UnsafeOutboundUrlError) {
      throw new BadRequestException(
        `Webhook URL rejected: ${error.reasonCode}`,
      );
    }
    throw error;
  }
}
