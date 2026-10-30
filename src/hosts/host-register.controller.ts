import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  Logger,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import type { FastifyRequest } from 'fastify';
import { callerAddress } from '../config/trusted-proxy';
import { CsrValidationError } from '../agents/certificate-authority.errors';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  HostRefusedError,
  HostRekeyPendingError,
  HostsService,
} from './hosts.service';
import { PlanLimitError } from '../entitlements/entitlements.service';
import { InstallKeyInvalidError } from './install-keys.service';
import {
  AdcsCertificateRejectedError,
  AdcsEnrolmentService,
} from './adcs/adcs-enrolment.service';
import {
  TpmAttestationError,
  TpmAttestationService,
} from './tpm/tpm-attestation.service';
import {
  RegisterAdcsRequestSchema,
  RegisterHostRequestSchema,
  TpmActivateSchema,
  TpmAkCertifySchema,
  TpmAkChallengeSchema,
  TpmChallengeSchema,
} from './hosts.validation';

/**
 * The machine-facing registration exchange (docs/hosts.md). Unauthenticated
 * by design, like `POST /agents/enroll`: the install key is the credential,
 * and every refusal looks the same to the caller.
 */
@ApiTags('hosts')
@Controller('hosts')
export class HostRegisterController {
  constructor(
    private readonly hosts: HostsService,
    private readonly config: ConfigService,
    private readonly adcs: AdcsEnrolmentService,
    private readonly tpm: TpmAttestationService,
  ) {}

  private address(request: FastifyRequest): string {
    return callerAddress(request.ip, {
      MANAR_TRUSTED_PROXY_CIDRS: this.config.get<string>(
        'MANAR_TRUSTED_PROXY_CIDRS',
      ),
    });
  }

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
      return await this.hosts.register({
        ...input,
        ip: this.address(request),
      });
    } catch (error) {
      if (error instanceof InstallKeyInvalidError) {
        throw new UnauthorizedException('Invalid install key');
      }
      if (error instanceof PlanLimitError) throw error.toHttp();
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

  @Post('register/adcs')
  @ApiOperation({
    summary:
      'Register a domain-joined machine with its AD CS computer certificate',
    description:
      'No install key. The certificate chain must lead to a customer CA the tenant trusts (validity, Client Authentication EKU, CRL). The body carries a proof signed by the certificate key over the tenant, machineId, CSR key and time. The host group comes from the machine OU read from AD; any doubt leaves the host PENDING.',
  })
  @ApiResponse({
    status: 201,
    description: '{ hostId, status, certificatePem, caChainPem }',
  })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async registerWithCertificate(
    @Req() request: FastifyRequest,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(RegisterAdcsRequestSchema, body);
    try {
      return await this.adcs.register({ ...input, ip: this.address(request) });
    } catch (error) {
      if (error instanceof AdcsCertificateRejectedError) {
        Logger.warn(error.message, HostRegisterController.name);
        throw new UnauthorizedException('Computer certificate not accepted');
      }
      if (error instanceof PlanLimitError) throw error.toHttp();
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

  @Post('tpm/challenge')
  @ApiOperation({
    summary: 'Start TPM credential activation',
    description:
      'Send the EK certificate chain and the TPMT_PUBLIC of the host key. The reply carries credentialBlob and encryptedSecret for TPM2_ActivateCredential; answer with POST /hosts/tpm/activate, then register with tpmChallengeId.',
  })
  @ApiResponse({
    status: 201,
    description: '{ challengeId, credentialBlob, encryptedSecret, expiresAt }',
  })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  async tpmChallenge(@Body() body: unknown) {
    const input = parseBodyOrThrow(TpmChallengeSchema, body);
    try {
      return await this.tpm.challenge(input);
    } catch (error) {
      if (error instanceof TpmAttestationError) {
        Logger.warn(error.message, HostRegisterController.name);
        throw new BadRequestException('TPM attestation request not accepted');
      }
      throw error;
    }
  }

  @Post('tpm/activate')
  @ApiOperation({
    summary: 'Complete TPM credential activation',
    description:
      'Send the secret the TPM recovered. Three wrong answers end the challenge.',
  })
  @ApiResponse({ status: 201, description: '{ verified: boolean }' })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  async tpmActivate(@Body() body: unknown) {
    const input = parseBodyOrThrow(TpmActivateSchema, body);
    try {
      return { verified: await this.tpm.activate(input) };
    } catch (error) {
      if (error instanceof TpmAttestationError) {
        throw new BadRequestException('TPM attestation request not accepted');
      }
      throw error;
    }
  }

  @Post('tpm/ak-challenge')
  @ApiOperation({
    summary: 'Start TPM attestation by a vendor-certified AK (Azure vTPM)',
    description:
      'For TPMs with an AK certificate instead of an EK certificate. Send machineId and the TPMT_PUBLIC of the host key; the reply carries a nonce to use as the qualifying data of TPM2_Certify. Answer with POST /hosts/tpm/ak-certify, then register with tpmChallengeId.',
  })
  @ApiResponse({
    status: 201,
    description: '{ challengeId, nonce, expiresAt }',
  })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  async tpmAkChallenge(@Body() body: unknown) {
    const input = parseBodyOrThrow(TpmAkChallengeSchema, body);
    try {
      return await this.tpm.akChallenge(input);
    } catch (error) {
      if (error instanceof TpmAttestationError) {
        Logger.warn(error.message, HostRegisterController.name);
        throw new BadRequestException('TPM attestation request not accepted');
      }
      throw error;
    }
  }

  @Post('tpm/ak-certify')
  @ApiOperation({
    summary: 'Complete TPM attestation by a vendor-certified AK',
    description:
      'Send the AK certificate chain, the host key TPMT_PUBLIC, and the TPM2_Certify result (TPMS_ATTEST and TPMT_SIGNATURE) made by the AK over the host key with the nonce as qualifying data. verified is false for anything that does not check out; three failures end the challenge.',
  })
  @ApiResponse({ status: 201, description: '{ verified: boolean }' })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  async tpmAkCertify(@Body() body: unknown) {
    const input = parseBodyOrThrow(TpmAkCertifySchema, body);
    try {
      return { verified: await this.tpm.akCertify(input) };
    } catch (error) {
      if (error instanceof TpmAttestationError) {
        throw new BadRequestException('TPM attestation request not accepted');
      }
      throw error;
    }
  }
}
