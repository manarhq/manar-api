import { Inject, Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { SECRET_PROVIDER } from '../database/secret-provider';
import type { SecretProvider } from '../database/secret-provider';
import {
  ToolActionNotFoundError,
  ToolDisabledError,
  ToolNotFoundError,
} from './credential-broker.errors';
import { HttpToolAdapter } from './http-tool.adapter';
import { McpToolAdapter } from './mcp-tool.adapter';
import type { ToolInvocationResult } from './tool-protocol-adapter.interface';
import { ToolRegistryService } from './tool-registry.service';

export interface CredentialBrokerInvokeInput {
  taskId: string;
  agentId: string;
  toolId: string;
  actionId: string;
  resource: string;
  params: unknown;
}

/**
 * The single place a resolved tool credential ever exists in this process
 * (Section 35). `invoke`:
 *
 *   1. Loads `Tool`/`ToolAction` (`ToolRegistryService`) — throws
 *      `ToolNotFoundError`/`ToolActionNotFoundError` if either doesn't
 *      resolve (no `ToolInvocation` row is possible here: its `toolId`/
 *      `actionId` columns are real foreign keys, so there is nothing valid
 *      to reference yet).
 *   2. Confirms `Tool.enabled` — a disabled tool fails cleanly even though
 *      `AuthorizationService` already ALLOWed (tool enablement is an
 *      operational concern, not an authorization decision). Unlike step 1,
 *      both ids are known by now, so this *does* record a `FAILURE`
 *      `ToolInvocation` row before throwing `ToolDisabledError`.
 *   3. Resolves the credential via the injected `SecretProvider`
 *      (`CompositeSecretProvider` — dispatches to `EnvSecretProvider` or
 *      `OpenBaoSecretProvider` based on `Tool.credentialReference.provider`,
 *      this service never branches on it itself). The resolved value is
 *      held only in a local variable for exactly as long as step 4 takes —
 *      never logged, never assigned to any field that could end up in the
 *      `ToolInvocation` row or the returned `ToolInvocationResult`.
 *   4. Dispatches to `HttpToolAdapter` or `McpToolAdapter` based on
 *      `Tool.protocol` — the identical two-adapter set, no separate path
 *      for either protocol.
 *   5. Records a `ToolInvocation` row (`SUCCESS`/`FAILURE`, timing,
 *      `resource`, a short `errorMessage` on failure) — never the resolved
 *      credential, never a raw request/response payload (an adapter's
 *      `ToolInvocationResult.errorMessage` is already a short,
 *      credential-free summary by construction — see that interface's doc
 *      comment).
 *   6. Returns the adapter's `ToolInvocationResult` unchanged — the
 *      credential is provably not part of it under any code path in this
 *      method (see the "credential never leaks" test, which greps the
 *      actual serialized response/DB row rather than trusting this
 *      comment).
 */
@Injectable()
export class CredentialBrokerService {
  private readonly logger = new Logger(CredentialBrokerService.name);

  constructor(
    private readonly toolRegistry: ToolRegistryService,
    @Inject(SECRET_PROVIDER) private readonly secretProvider: SecretProvider,
    private readonly httpAdapter: HttpToolAdapter,
    private readonly mcpAdapter: McpToolAdapter,
  ) {}

  async invoke(
    tenantClient: TenantPrismaClient,
    input: CredentialBrokerInvokeInput,
  ): Promise<ToolInvocationResult> {
    const resolved = await this.toolRegistry.findToolAction(
      tenantClient,
      input.toolId,
      input.actionId,
    );
    if (!resolved) {
      const tool = await this.toolRegistry.findToolByName(
        tenantClient,
        input.toolId,
      );
      if (!tool) throw new ToolNotFoundError(input.toolId);
      throw new ToolActionNotFoundError(input.toolId, input.actionId);
    }
    const { tool, action } = resolved;

    if (!tool.enabled) {
      await this.recordInvocation(tenantClient, input, {
        status: 'FAILURE',
        startedAt: new Date(),
        completedAt: new Date(),
        errorMessage: 'Tool is disabled',
        toolRowId: tool.id,
        actionRowId: action.id,
      });
      throw new ToolDisabledError(input.toolId);
    }

    const startedAt = new Date();
    let result: ToolInvocationResult;
    try {
      const credential = await this.secretProvider.resolve(
        tool.credentialReference,
      );
      const adapter =
        tool.protocol === 'MCP' ? this.mcpAdapter : this.httpAdapter;
      result = await adapter.invoke(
        tool,
        action,
        input.resource,
        input.params,
        credential,
      );
    } catch (error) {
      // Credential resolution or an adapter-internal throw (never expected
      // from either adapter's own contract, which always resolves to a
      // ToolInvocationResult -- this is a defensive fallback). Logged
      // server-side only; the stored/returned message is a fixed, generic
      // string -- never the raw error, which for a credential-resolution
      // failure could in principle describe *why* (e.g. a KV path), never
      // the secret *value* itself, but there is no reason to take that
      // risk when a generic message is just as actionable operationally.
      this.logger.error(
        `Tool invocation for "${input.toolId}/${input.actionId}" failed before a result could be produced`,
        error instanceof Error ? error.stack : undefined,
      );
      result = { success: false, errorMessage: 'tool invocation failed' };
    }

    await this.recordInvocation(tenantClient, input, {
      status: result.success ? 'SUCCESS' : 'FAILURE',
      startedAt,
      completedAt: new Date(),
      errorMessage: result.success
        ? null
        : (result.errorMessage ?? 'unknown error'),
      toolRowId: tool.id,
      actionRowId: action.id,
    });

    return result;
  }

  private async recordInvocation(
    tenantClient: TenantPrismaClient,
    input: CredentialBrokerInvokeInput,
    record: {
      status: 'SUCCESS' | 'FAILURE';
      startedAt: Date;
      completedAt: Date;
      errorMessage: string | null;
      toolRowId: string;
      actionRowId: string;
    },
  ): Promise<void> {
    await tenantClient.toolInvocation.create({
      data: {
        taskId: input.taskId,
        agentId: input.agentId,
        toolId: record.toolRowId,
        actionId: record.actionRowId,
        resource: input.resource,
        status: record.status,
        startedAt: record.startedAt,
        completedAt: record.completedAt,
        errorMessage: record.errorMessage,
      },
    });
  }
}
