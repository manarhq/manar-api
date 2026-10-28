import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../../agents/parse-body.util';
import type { AuditActor } from '../../audit/audit-event-types';
import { CurrentAuth } from '../../auth/auth-context';
import type { AuthContext } from '../../auth/auth-context';
import { JwtAuthGuard } from '../../auth/jwt-auth.guard';
import { RequireRole } from '../../auth/require-role.decorator';
import { RolesGuard } from '../../auth/roles.guard';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import {
  AdcsSettingsSchema,
  AdcsTrustedCaSchema,
  AdOuRuleSchema,
  UpdateAdOuRuleSchema,
} from '../hosts.validation';
import {
  TpmAttestationError,
  TpmAttestationService,
} from '../tpm/tpm-attestation.service';
import { AdcsAdminService, AdcsConfigError } from './adcs-admin.service';
import { CertChainError } from './cert-chain.util';

const WRITE = ['SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const READ = ['AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const actorOf = (auth: AuthContext): AuditActor => ({
  type: 'human',
  id: auth.user.id,
});

function http(error: unknown): never {
  if (
    error instanceof AdcsConfigError ||
    error instanceof TpmAttestationError ||
    error instanceof CertChainError
  ) {
    throw new BadRequestException(error.message);
  }
  const code = (error as { code?: string } | null)?.code;
  if (code === 'P2025') throw new NotFoundException('not found');
  if (code === 'P2002') throw new BadRequestException('already exists');
  if (code === 'P2003') throw new BadRequestException('unknown host group');
  throw error;
}

/** Key-less enrolment configuration: customer CAs, AD connection, OU rules, TPM roots, re-sync. */
@ApiTags('hosts')
@ApiBearerAuth('jwt')
@Controller()
@UseGuards(JwtAuthGuard, RolesGuard)
export class AdcsAdminController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly admin: AdcsAdminService,
    private readonly tpm: TpmAttestationService,
  ) {}

  private client(auth: AuthContext) {
    return this.tenants.getClient(auth.tenant.id);
  }

  @Get('adcs/trusted-cas')
  @RequireRole(...READ)
  @ApiOperation({
    summary: 'List the customer CA certificates this tenant trusts',
  })
  async listCas(@CurrentAuth() auth: AuthContext) {
    return this.admin.listCas(await this.client(auth));
  }

  @Post('adcs/trusted-cas')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary:
      'Trust a customer CA certificate for computer-certificate enrolment (audited)',
  })
  async addCa(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(AdcsTrustedCaSchema, body);
    return Promise.resolve()
      .then(async () =>
        this.admin.addCa(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          input,
        ),
      )
      .catch(http);
  }

  @Delete('adcs/trusted-cas/:id')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary: 'Stop trusting a customer CA certificate (audited)',
  })
  async removeCa(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return Promise.resolve()
      .then(async () =>
        this.admin.removeCa(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          id,
        ),
      )
      .catch(http);
  }

  @Get('adcs/settings')
  @RequireRole(...READ)
  @ApiOperation({
    summary: 'AD connection settings (the bind password is never returned)',
  })
  async getSettings(@CurrentAuth() auth: AuthContext) {
    return this.admin.getSettings(await this.client(auth), auth.tenant.id);
  }

  @Put('adcs/settings')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary:
      'Set the AD connection (LDAPS only) and the default host group (audited)',
    description:
      'bindPassword is write-only and stored in OpenBao KV, never in the database. The LDAPS server certificate is verified against serverCaPem.',
  })
  async putSettings(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(AdcsSettingsSchema, body);
    return Promise.resolve()
      .then(async () =>
        this.admin.putSettings(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          input,
        ),
      )
      .catch(http);
  }

  @Get('adcs/ou-rules')
  @RequireRole(...READ)
  @ApiOperation({ summary: 'List AD OU to host group rules' })
  async listOuRules(@CurrentAuth() auth: AuthContext) {
    return this.admin.listOuRules(await this.client(auth));
  }

  @Post('adcs/ou-rules')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary:
      'Map an AD OU (DN suffix, longest match wins) to a host group (audited)',
  })
  async createOuRule(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(AdOuRuleSchema, body);
    return Promise.resolve()
      .then(async () =>
        this.admin.createOuRule(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          input,
        ),
      )
      .catch(http);
  }

  @Patch('adcs/ou-rules/:id')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Change the host group of an OU rule (audited)' })
  async updateOuRule(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(UpdateAdOuRuleSchema, body);
    return Promise.resolve()
      .then(async () =>
        this.admin.updateOuRule(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          id,
          input,
        ),
      )
      .catch(http);
  }

  @Delete('adcs/ou-rules/:id')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Delete an OU rule (audited)' })
  async deleteOuRule(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return Promise.resolve()
      .then(async () =>
        this.admin.deleteOuRule(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          id,
        ),
      )
      .catch(http);
  }

  @Post('adcs/resync')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary:
      'Re-read the OU of every computer-certificate host from AD and move hosts (audited)',
    description:
      'AD unreachable: nothing changes and status says so. Status of a host is never changed.',
  })
  async resync(@CurrentAuth() auth: AuthContext) {
    return this.admin.resync(
      await this.client(auth),
      auth.tenant.id,
      actorOf(auth),
    );
  }

  @Get('tpm-trust-roots')
  @RequireRole(...READ)
  @ApiOperation({
    summary:
      'List the TPM manufacturer roots this tenant accepts for EK certificates',
  })
  async listRoots(@CurrentAuth() auth: AuthContext) {
    return this.tpm.listRoots(await this.client(auth));
  }

  @Post('tpm-trust-roots')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary:
      'Accept a TPM manufacturer root (or intermediate) for EK certificates (audited)',
  })
  async addRoot(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(AdcsTrustedCaSchema, body);
    return Promise.resolve()
      .then(async () =>
        this.tpm.addRoot(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          input,
        ),
      )
      .catch(http);
  }

  @Delete('tpm-trust-roots/:id')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Remove a TPM trust root (audited)' })
  async removeRoot(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return Promise.resolve()
      .then(async () =>
        this.tpm.removeRoot(
          await this.client(auth),
          auth.tenant.id,
          actorOf(auth),
          id,
        ),
      )
      .catch(http);
  }
}
