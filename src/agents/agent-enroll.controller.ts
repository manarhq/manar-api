import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Logger,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TenantNotFoundError } from '../database/tenant-database.errors';
import { AgentsService } from './agents.service';
import { EnrollAgentRequestSchema } from './agents.validation';
import { CsrValidationError } from './certificate-authority.errors';
import { EnrollmentTokenInvalidError } from './agents.errors';
import { parseEnrollmentTokenParts } from './enrollment-token.util';
import { parseBodyOrThrow } from './parse-body.util';
import {
  EdgeAddressPoolExhaustedError,
  EdgeKeyInUseError,
  EdgePeerService,
} from '../edge/edge-peer.service';
import { isWgPublicKey } from '../edge/edge-net';
import { ensureHostClaudeCodeTool } from '../tools/host-actions';

/**
 * `POST /agents/enroll` — the agent-facing half of Section 14's enrollment
 * flow. Deliberately unauthenticated by `JwtAuthGuard`/`RolesGuard`: an
 * enrolling agent has no JWT, only the one-time enrollment token minted by
 * `AgentsController`. The token itself is what authenticates this request
 * (single-use, hashed at rest, short expiry — see
 * `enrollment-token.util.ts`), which is why every failure path below
 * returns a uniform 401 with no detail about *why* the token didn't work
 * (unknown tenant, unknown token, already used, expired all look the same
 * to the caller) — distinguishing them would let an attacker probe which
 * tenants/tokens exist.
 */
@Controller('agents')
export class AgentEnrollController {
  private readonly logger = new Logger(AgentEnrollController.name);

  constructor(
    private readonly agentsService: AgentsService,
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly edgePeers: EdgePeerService,
  ) {}

  @Post('enroll')
  async enroll(@Body() body: unknown) {
    const input = parseBodyOrThrow(EnrollAgentRequestSchema, body);
    // Edge off and a malformed key are refused before the token is looked at; key ownership and
    // address capacity are checked read-only before the token is spent (see below).
    if (input.edge) {
      if (!this.edgePeers.enabled) {
        throw new BadRequestException({
          statusCode: 400,
          code: 'edge_not_enabled',
          message: 'edge_not_enabled',
        });
      }
      if (!isWgPublicKey(input.edge.wgPublicKey)) {
        throw new BadRequestException(
          'Invalid edge.wgPublicKey: expected base64 of 32 bytes',
        );
      }
    }

    const tokenParts = parseEnrollmentTokenParts(input.token);
    if (!tokenParts) {
      throw new UnauthorizedException('Invalid enrollment token');
    }

    const tenant = await this.control.tenant.findUnique({
      where: { slug: tokenParts.tenantSlug },
    });
    if (!tenant) {
      throw new UnauthorizedException('Invalid enrollment token');
    }

    const tenantClient = await this.resolveTenantClientOrUnauthorized(
      tenant.id,
    );

    // An edge request runs only for a token that verifies (read-only, not consumed; the agent it
    // names): anything else gets the uniform 401 here, before a token is spent or a certificate
    // signed, and an unauthenticated caller learns nothing about keys or the address pool.
    if (input.edge) {
      const verified = await this.agentsService.verifyEnrollmentToken(
        tenantClient,
        input.token,
        tokenParts.agentSlug,
      );
      if (!verified)
        throw new UnauthorizedException('Invalid enrollment token');
      try {
        await this.edgePeers.preflight({
          tenantId: tenant.id,
          agentId: verified.agentId,
          publicKey: input.edge.wgPublicKey,
        });
      } catch (error) {
        if (
          error instanceof EdgeKeyInUseError ||
          error instanceof EdgeAddressPoolExhaustedError
        )
          throw new ConflictException(error.message);
        throw error;
      }
    }

    try {
      const issued = await this.agentsService.enroll(
        tenantClient,
        tenant.id,
        input.token,
        input.csr,
      );

      const response = {
        certificate: issued.certificatePem,
        caChain: issued.caChainPem,
        serialNumber: issued.serialNumber,
        notBefore: issued.notBefore,
        notAfter: issued.notAfter,
      };
      if (!input.edge) return response;
      // One peer per agent; a re-enrollment replaces its key and keeps its address. Should the
      // edge step still fail (a race the preflight could not see), the certificate just signed
      // is revoked before answering, so no live certificate exists that was never returned.
      let edge;
      try {
        edge = await this.edgePeers.enroll({
          tenantId: tenant.id,
          tenantSlug: tenant.slug,
          agentId: issued.agentId,
          agentSlug: issued.agentSlug,
          publicKey: input.edge.wgPublicKey,
        });
      } catch (edgeError) {
        await this.agentsService
          .revokeEnrollmentCertificate(
            tenantClient,
            tenant.id,
            issued.agentId,
            issued.serialNumber,
          )
          .catch((revokeError: Error) =>
            this.logger.error(
              `could not revoke certificate ${issued.serialNumber} after a failed edge enrollment: ${revokeError.message}`,
            ),
          );
        throw edgeError;
      }
      // The host's local actions (Claude Code hook) get their risk metadata in this tenant.
      await ensureHostClaudeCodeTool(tenantClient).catch((error: Error) =>
        this.logger.error(`host tool registration failed: ${error.message}`),
      );
      return { ...response, edge };
    } catch (error) {
      if (error instanceof EnrollmentTokenInvalidError) {
        throw new UnauthorizedException('Invalid enrollment token');
      }
      if (error instanceof EdgeKeyInUseError) {
        throw new ConflictException(error.message);
      }
      if (error instanceof EdgeAddressPoolExhaustedError) {
        throw new ConflictException(error.message);
      }
      if (error instanceof CsrValidationError) {
        // Not a 401: the token itself was valid (it's what got us this
        // far) — the CSR the agent submitted is what's rejected, which is
        // a client request error, not an authentication failure.
        throw new BadRequestException(error.message);
      }
      throw error;
    }
  }

  private async resolveTenantClientOrUnauthorized(tenantId: string) {
    try {
      return await this.tenantDatabaseManager.getClient(tenantId);
    } catch (error) {
      if (error instanceof TenantNotFoundError) {
        throw new UnauthorizedException('Invalid enrollment token');
      }
      throw error;
    }
  }
}
