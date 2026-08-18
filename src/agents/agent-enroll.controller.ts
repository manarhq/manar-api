import {
  BadRequestException,
  Body,
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
  ) {}

  @Post('enroll')
  async enroll(@Body() body: unknown) {
    const input = parseBodyOrThrow(EnrollAgentRequestSchema, body);

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

    try {
      const issued = await this.agentsService.enroll(
        tenantClient,
        input.token,
        input.csr,
      );

      return {
        certificate: issued.certificatePem,
        caChain: issued.caChainPem,
        serialNumber: issued.serialNumber,
        notBefore: issued.notBefore,
        notAfter: issued.notAfter,
      };
    } catch (error) {
      if (error instanceof EnrollmentTokenInvalidError) {
        throw new UnauthorizedException('Invalid enrollment token');
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
