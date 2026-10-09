import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { SecretReferenceDescriptor } from '../database/secret-provider';
import type { DataClassification } from '../common/data-classification';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';

/**
 * Validates a `Tool.credentialReference` JSONB column back into a typed
 * `SecretReferenceDescriptor` (`src/database/secret-provider.ts`) — the
 * exact same interface `TenantDatabaseManager`/`CompositeSecretProvider`
 * already use for the control DB's `SecretReference` rows, reused here
 * rather than inventing a second credential-pointer shape. Throws on
 * malformed stored data — fail-closed, matching `parseToolActions`'
 * (`src/authorization/grant-triples.ts`) precedent for every other
 * validated-at-write-time-but-still-checked-at-read-time JSON column in
 * this schema.
 */
const SecretReferenceDescriptorSchema = z.object({
  provider: z.enum(['ENV', 'OPENBAO', 'CONTROL_DB']),
  reference: z.string().min(1),
});

/**
 * The subset of a `Tool` row this module operates on — a narrow structural
 * shape rather than the full generated Prisma model type, matching this
 * codebase's established convention at service boundaries (see
 * `TasksService`'s `TaskRecord`).
 */
export interface ToolRecord {
  id: string;
  name: string;
  type: string;
  vendor: string | null;
  description: string | null;
  baseEndpoint: string;
  protocol: 'HTTP' | 'MCP' | 'MICROSOFT' | 'GITLAB';
  credentialReference: SecretReferenceDescriptor;
  enabled: boolean;
  metadata: unknown;
}

/** The subset of a `ToolAction` row this module operates on — see `ToolRecord`'s doc comment. */
export interface ToolActionRecord {
  id: string;
  toolId: string;
  name: string;
  description: string | null;
  riskBaseScore: number;
  inputSchema: unknown;
  outputSchema: unknown;
  mutating: boolean;
  destructive: boolean;
  approvalDefault: boolean;
  /** Phase 15a (Section 53) — see `DataClassification`'s doc comment (`src/common/data-classification.ts`). Defaults to `INTERNAL` at the schema level; always present on a real row. */
  classification: DataClassification;
}

export interface ListToolsInput {
  /** Section 65's tools list filter — a tool's operational health/enabled status. */
  enabled?: boolean;
  limit: number;
  cursor?: DecodedCursor;
}

export interface ToolWithActions extends Omit<
  ToolRecord,
  'credentialReference'
> {
  createdAt: Date;
  actions: ToolActionRecord[];
}

/**
 * Read-only lookups against the `Tool`/`ToolAction` registry (Phase 7b),
 * shared by `CredentialBrokerService` (which needs to fail loudly if a
 * tool/action doesn't exist before ever attempting an invocation) and
 * `RiskEngine` (which needs the exact opposite: a silent `null` for a
 * `{toolId, actionId}` pair that was never registered as a real tool at
 * all — the overwhelming majority of Phase 5/6's own pre-existing tests
 * use made-up `toolId`/`actionId` strings with no Tool Registry entry, and
 * must keep authorizing exactly as before; see `RiskEngine`'s own doc
 * comment for how it uses `null` here). One implementation, not two copies
 * of the same `Tool.name` -> `ToolAction.name` resolution that could
 * drift.
 *
 * `Task.allowedToolActions[].toolId` / `AuthorizeRequest.toolId` (Phase 5)
 * were always opaque, caller-supplied strings, validated only for shape —
 * this phase does not change that contract at all (no schema change to
 * `Task`, `AuthorizeRequest`, or the OpenFGA model). What changes is that
 * those same strings *may* now also resolve against a real `Tool.name`/
 * `ToolAction.name` row here, once one has actually been registered — see
 * docs/tool-gateway.md.
 */
@Injectable()
export class ToolRegistryService {
  async findToolByName(
    tenantClient: TenantPrismaClient,
    name: string,
  ): Promise<ToolRecord | null> {
    const row = await tenantClient.tool.findUnique({ where: { name } });
    return row ? this.toToolRecord(row) : null;
  }

  /**
   * Resolves `{ toolId, actionId }` (the same opaque strings the
   * authorize pipeline already validated) against real `Tool.name` /
   * `ToolAction.name` rows. `null` if either the tool or the action isn't
   * registered — a normal, expected outcome for any request that predates
   * this phase's registry or simply never registered that tool, not an
   * error.
   */
  async findToolAction(
    tenantClient: TenantPrismaClient,
    toolId: string,
    actionId: string,
  ): Promise<{ tool: ToolRecord; action: ToolActionRecord } | null> {
    const tool = await this.findToolByName(tenantClient, toolId);
    if (!tool) return null;

    const actionRow = await tenantClient.toolAction.findUnique({
      where: { toolId_name: { toolId: tool.id, name: actionId } },
    });
    if (!actionRow) return null;

    return { tool, action: this.toToolActionRecord(actionRow) };
  }

  /**
   * `GET /tools` (Phase 11b Part 1) — cursor-paginated, newest first, with
   * its `ToolAction` rows embedded (Section 65's spec for this resource is
   * literally "Tool (+ToolAction)" — a tool's actions are what a policy
   * author/operator actually needs alongside it, and the per-tool action
   * count is small enough that embedding the full array beats a second,
   * separately-paginated endpoint). Deliberately never includes
   * `credentialReference` — even though it's only a *pointer* (never the
   * resolved credential value), this mirrors `WebhookEndpointResponseDto`'s
   * identical "never expose secret-adjacent fields over this HTTP surface"
   * posture (see that DTO's own doc comment).
   */
  async list(
    tenantClient: TenantPrismaClient,
    input: ListToolsInput,
  ): Promise<CursorPage<ToolWithActions>> {
    const where = {
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
      ...cursorWhereClause('createdAt', input.cursor),
    };
    const rows = await tenantClient.tool.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
      include: { actions: { orderBy: { name: 'asc' } } },
    });
    const withActions: ToolWithActions[] = rows.map((row) => {
      const record = this.toToolRecord(row);
      return {
        id: record.id,
        name: record.name,
        type: record.type,
        vendor: record.vendor,
        description: record.description,
        baseEndpoint: record.baseEndpoint,
        protocol: record.protocol,
        enabled: record.enabled,
        metadata: record.metadata,
        createdAt: row.createdAt,
        actions: row.actions.map((action) => this.toToolActionRecord(action)),
      };
    });
    return toCursorPage(withActions, input.limit, (row) => row.createdAt);
  }

  private toToolRecord(row: {
    id: string;
    name: string;
    type: string;
    vendor: string | null;
    description: string | null;
    baseEndpoint: string;
    protocol: string;
    credentialReference: unknown;
    enabled: boolean;
    metadata: unknown;
  }): ToolRecord {
    return {
      id: row.id,
      name: row.name,
      type: row.type,
      vendor: row.vendor,
      description: row.description,
      baseEndpoint: row.baseEndpoint,
      protocol: row.protocol as ToolRecord['protocol'],
      credentialReference: SecretReferenceDescriptorSchema.parse(
        row.credentialReference,
      ),
      enabled: row.enabled,
      metadata: row.metadata,
    };
  }

  private toToolActionRecord(row: {
    id: string;
    toolId: string;
    name: string;
    description: string | null;
    riskBaseScore: number;
    inputSchema: unknown;
    outputSchema: unknown;
    mutating: boolean;
    destructive: boolean;
    approvalDefault: boolean;
    classification: string;
  }): ToolActionRecord {
    return { ...row, classification: row.classification as DataClassification };
  }
}
