import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  Query,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { IdempotencyInterceptor } from '../idempotency/idempotency.interceptor';
import type { FastifyReply } from 'fastify';
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
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import {
  dumpPolicyContentYaml,
  resolveSubmittedContent,
} from './policy-content-codec';
import { PolicyContent } from './policy-content.schema';
import {
  PolicyNotFoundError,
  PolicyVersionNotDraftError,
  PolicyVersionNotFoundError,
} from './policy.errors';
import { PolicyService } from './policy.service';
import {
  CreatePolicyRequestSchema,
  CreatePolicyVersionRequestSchema,
} from './policy.validation';
import {
  CreatePolicyRequestDto,
  CreatePolicyResponseDto,
  CreatePolicyVersionRequestDto,
  GetPolicyResponseDto,
  PolicyListResponseDto,
  PolicyVersionResponseDto,
} from './policy.dto';

/** Translates the service layer's typed domain errors into HTTP responses — same pattern `AgentsController`'s `mapAgentNotFound` establishes. */
async function mapPolicyErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof PolicyNotFoundError ||
      error instanceof PolicyVersionNotFoundError
    ) {
      throw new NotFoundException(error.message);
    }
    if (error instanceof PolicyVersionNotDraftError) {
      throw new ConflictException(error.message);
    }
    throw error;
  }
}

/** Resolves `content`/`contentYaml` into a validated `PolicyContent`, mapping any schema-validation failure (malformed JSON shape, or YAML that fails `PolicyContentSchema` once parsed) to a 400 — same "no stack trace leaked" convention `parseBodyOrThrow` uses. */
function resolveContentOrThrow(body: {
  content?: unknown;
  contentYaml?: string;
}): PolicyContent {
  try {
    return resolveSubmittedContent(body);
  } catch (error) {
    throw new BadRequestException(
      `Invalid policy content: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Human-facing policy management (Sections 21-22) — JWT-guarded, entirely
 * separate from the mTLS agent surface (`AuthorizeController` is the only
 * consumer of `PolicyEngine` on that side, and never exposes any of this).
 * Gated the same way `TasksController` is
 * (`SECURITY_ADMIN`/`TENANT_OWNER`/`AI_GOVERNANCE_MANAGER`) for every
 * endpoint except publishing, which the design spec calls out explicitly
 * as narrower (`SECURITY_ADMIN`/`TENANT_OWNER` only — no
 * `AI_GOVERNANCE_MANAGER`) — a method-level `@RequireRole(...)` overrides
 * the class-level one (`RolesGuard` uses `getAllAndOverride`, handler
 * metadata wins).
 *
 * **There is no update or delete endpoint for a published `PolicyVersion`
 * anywhere in this controller, permanently** (Section 21/22 — published
 * versions are immutable) — editing always means `POST
 * /policies/:id/versions` (a new `DRAFT`), and a rollback is likewise a
 * new version whose `content` happens to match an older one (see
 * docs/policy-model.md). This is not "not built yet"; it will never be
 * built.
 */
@ApiTags('policies')
@ApiBearerAuth('jwt')
@Controller('policies')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER', 'AI_GOVERNANCE_MANAGER')
export class PolicyController {
  constructor(
    private readonly policyService: PolicyService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Create a policy (with its first DRAFT version)',
    description:
      'Provide exactly one of `content` (JSON) or `contentYaml` (YAML) — both validate against the same PolicyContentSchema.',
  })
  @ApiBody({ type: CreatePolicyRequestDto })
  @ApiResponse({ status: 201, type: CreatePolicyResponseDto })
  @ApiResponse({
    status: 400,
    type: ErrorResponseDto,
    description: 'Invalid body, or invalid policy content.',
  })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async createPolicy(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(CreatePolicyRequestSchema, body);
    const content = resolveContentOrThrow(input);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    const { policy, version } = await this.policyService.createPolicy(
      tenantClient,
      {
        name: input.name,
        description: input.description ?? null,
        content,
        authorId: auth.user.id,
        reason: input.reason ?? null,
      },
    );

    return {
      id: policy.id,
      name: policy.name,
      description: policy.description,
      createdAt: policy.createdAt,
      latestVersion: shapeVersion(version),
    };
  }

  @Post(':id/versions')
  @ApiOperation({
    summary: 'Create a new DRAFT version of a policy',
    description:
      'Provide exactly one of `content`, `contentYaml`, or `rollbackToVersionId`. There is no update/delete endpoint for a published version — published versions are immutable; editing always means creating a new DRAFT here.',
  })
  @ApiParam({ name: 'id', description: 'Policy ID', format: 'uuid' })
  @ApiBody({ type: CreatePolicyVersionRequestDto })
  @ApiResponse({ status: 201, type: PolicyVersionResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Policy (or rollback target version) not found.',
  })
  async createVersion(
    @CurrentAuth() auth: AuthContext,
    @Param('id') policyId: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(CreatePolicyVersionRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    return mapPolicyErrors(async () => {
      let content: PolicyContent;
      let reason = input.reason ?? null;

      if (input.rollbackToVersionId) {
        const target = await this.policyService.getVersionOrThrow(
          tenantClient,
          policyId,
          input.rollbackToVersionId,
        );
        // Already-validated, already-stored content -- re-parsing it
        // through resolveSubmittedContent would be redundant work for no
        // extra safety, since it was validated once at write time and is
        // never mutated afterward (PolicyVersion is immutable).
        content = target.content as PolicyContent;
        reason = reason
          ? `${reason} (rollback to version ${target.version})`
          : `Rollback to version ${target.version}`;
      } else {
        content = resolveContentOrThrow(input);
      }

      const version = await this.policyService.createVersion(
        tenantClient,
        policyId,
        { content, authorId: auth.user.id, reason },
      );
      return shapeVersion(version);
    });
  }

  @Post(':id/versions/:versionId/publish')
  @RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
  @UseInterceptors(IdempotencyInterceptor)
  @ApiOperation({
    summary: 'Publish a DRAFT policy version',
    description:
      'Narrower than the other endpoints on this controller: requires SECURITY_ADMIN or TENANT_OWNER only (no AI_GOVERNANCE_MANAGER). The version must currently be DRAFT. Supports an `Idempotency-Key` header (Phase 12a, Section 8) — a replay with the same key returns the original response without re-publishing.',
  })
  @ApiParam({ name: 'id', description: 'Policy ID', format: 'uuid' })
  @ApiParam({
    name: 'versionId',
    description: 'PolicyVersion ID',
    format: 'uuid',
  })
  @ApiResponse({ status: 201, type: PolicyVersionResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Policy or version not found.',
  })
  @ApiResponse({
    status: 409,
    type: ErrorResponseDto,
    description: 'Version is not DRAFT.',
  })
  async publishVersion(
    @CurrentAuth() auth: AuthContext,
    @Param('id') policyId: string,
    @Param('versionId') versionId: string,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    const published = await mapPolicyErrors(() =>
      this.policyService.publishVersion(
        tenantClient,
        auth.tenant.id,
        policyId,
        versionId,
        auth.user.id,
      ),
    );
    return shapeVersion(published);
  }

  @Get()
  @ApiOperation({
    summary: 'List policies',
    description:
      'Cursor-paginated, newest first. Each row includes its current PUBLISHED version, exactly like GET /policies/:id.',
  })
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
  @ApiResponse({ status: 200, type: PolicyListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async listPolicies(
    @CurrentAuth() auth: AuthContext,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const page = await this.policyService.listPolicies(tenantClient, {
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
    return {
      items: page.items.map((policy) => ({
        id: policy.id,
        name: policy.name,
        description: policy.description,
        createdAt: policy.createdAt,
        currentVersion: policy.currentVersion
          ? shapeVersion(policy.currentVersion)
          : null,
      })),
      nextCursor: page.nextCursor,
    };
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get a policy and its current published version',
  })
  @ApiParam({ name: 'id', description: 'Policy ID', format: 'uuid' })
  @ApiResponse({ status: 200, type: GetPolicyResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Policy not found.',
  })
  async getPolicy(
    @CurrentAuth() auth: AuthContext,
    @Param('id') policyId: string,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    const { policy, current } = await mapPolicyErrors(() =>
      this.policyService.getCurrentPublished(tenantClient, policyId),
    );

    return {
      id: policy.id,
      name: policy.name,
      description: policy.description,
      createdAt: policy.createdAt,
      currentVersion: current ? shapeVersion(current) : null,
    };
  }

  @Get(':id/versions')
  @ApiOperation({ summary: 'List every version of a policy' })
  @ApiParam({ name: 'id', description: 'Policy ID', format: 'uuid' })
  @ApiResponse({ status: 200, type: PolicyVersionResponseDto, isArray: true })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Policy not found.',
  })
  async listVersions(
    @CurrentAuth() auth: AuthContext,
    @Param('id') policyId: string,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    const versions = await mapPolicyErrors(() =>
      this.policyService.listVersions(tenantClient, policyId),
    );
    return versions.map(shapeVersion);
  }

  @Get(':id/versions/:versionId')
  @ApiOperation({
    summary: 'Get one policy version',
    description:
      'With `?format=yaml`, returns the content as a `text/yaml` document instead of the normal JSON envelope.',
  })
  @ApiParam({ name: 'id', description: 'Policy ID', format: 'uuid' })
  @ApiParam({
    name: 'versionId',
    description: 'PolicyVersion ID',
    format: 'uuid',
  })
  @ApiQuery({
    name: 'format',
    required: false,
    enum: ['yaml'],
    description: 'Pass "yaml" to receive text/yaml instead of JSON.',
  })
  @ApiResponse({ status: 200, type: PolicyVersionResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Policy or version not found.',
  })
  async getVersion(
    @CurrentAuth() auth: AuthContext,
    @Param('id') policyId: string,
    @Param('versionId') versionId: string,
    @Query('format') format: string | undefined,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    const version = await mapPolicyErrors(() =>
      this.policyService.getVersionOrThrow(tenantClient, policyId, versionId),
    );

    if (format === 'yaml') {
      reply.header('Content-Type', 'text/yaml; charset=utf-8');
      return dumpPolicyContentYaml(version.content as PolicyContent);
    }

    return shapeVersion(version);
  }
}

/** Shapes a `PolicyVersion` row for an API response -- the same fields regardless of which endpoint returned it. */
function shapeVersion(version: {
  id: string;
  policyId: string;
  version: number;
  status: string;
  content: unknown;
  contentHash: string;
  authorId: string;
  reason: string | null;
  previousVersionId: string | null;
  publishedAt: Date | null;
  createdAt: Date;
}) {
  return {
    id: version.id,
    policyId: version.policyId,
    version: version.version,
    status: version.status,
    content: version.content,
    contentHash: version.contentHash,
    authorId: version.authorId,
    reason: version.reason,
    previousVersionId: version.previousVersionId,
    publishedAt: version.publishedAt,
    createdAt: version.createdAt,
  };
}
