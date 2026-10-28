import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { CsrValidationError } from '../agents/certificate-authority.errors';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  HostRefusedError,
  HostRekeyPendingError,
  HostsService,
} from './hosts.service';
import { InstallKeyInvalidError } from './install-keys.service';
import { RegisterHostRequestSchema } from './hosts.validation';

/**
 * The machine-facing registration exchange (docs/hosts.md). Unauthenticated
 * by design, like `POST /agents/enroll`: the install key is the credential,
 * and every refusal looks the same to the caller.
 */
@ApiTags('hosts')
@Controller('hosts')
export class HostRegisterController {
  constructor(private readonly hosts: HostsService) {}

  @Post('register')
  @ApiOperation({
    summary: 'Register a machine with an install key',
    description:
      'manar-edge sends an install key, a CSR whose only URI SAN is host://<tenantSlug>/<machineId>, and the machine facts. Returns the host id, its status (PENDING until an approval rule or an admin approves it) and a host certificate.',
  })
  @ApiResponse({
    status: 201,
    description: '{ hostId, status, certificatePem, caChainPem }',
  })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async register(@Req() request: FastifyRequest, @Body() body: unknown) {
    const input = parseBodyOrThrow(RegisterHostRequestSchema, body);
    try {
      return await this.hosts.register({ ...input, ip: request.ip });
    } catch (error) {
      if (error instanceof InstallKeyInvalidError) {
        throw new UnauthorizedException('Invalid install key');
      }
      if (error instanceof HostRekeyPendingError) {
        throw new ConflictException({
          code: 'host_rekey_pending',
          message:
            'This machine is known with another key or group; an admin must approve the change',
        });
      }
      if (error instanceof HostRefusedError) {
        throw new ForbiddenException('This machine is not allowed to register');
      }
      if (error instanceof CsrValidationError) {
        throw new BadRequestException(error.message);
      }
      throw error;
    }
  }
}
