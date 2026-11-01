import { ApiProperty } from '@nestjs/swagger';
import { z } from 'zod';
import { ROLES } from '../auth/roles';

export const CompanyTrialRequestSchema = z.object({
  displayName: z.string().trim().min(1).max(120),
});
export const SwitchWorkspaceRequestSchema = z.object({
  tenantId: z.string().min(1).max(64),
});
export const DecideJoinRequestSchema = z.object({
  role: z.enum(ROLES).optional(),
});

export class WorkspaceSummaryDto {
  @ApiProperty() tenantId!: string;
  @ApiProperty() name!: string;
  @ApiProperty({ enum: ['PERSONAL', 'COMPANY', 'SAMPLE'] }) kind!: string;
  @ApiProperty({
    description:
      'ACTIVE when ready; QUEUED or PROVISIONING while it is being set up.',
  })
  status!: string;
  @ApiProperty({ enum: ['ACTIVE', 'PENDING', 'REMOVED'] })
  membershipStatus!: string;
  @ApiProperty({ enum: ROLES, isArray: true }) roles!: string[];
}

export class WorkspaceListResponseDto {
  @ApiProperty({ type: () => WorkspaceSummaryDto, isArray: true })
  items!: WorkspaceSummaryDto[];
}

export class CreateWorkspaceResponseDto {
  @ApiProperty() tenantId!: string;
  @ApiProperty({ enum: ['ACTIVE', 'QUEUED'] }) status!: string;
}

export class CompanyInfoDto {
  @ApiProperty() tenantId!: string;
  @ApiProperty() name!: string;
  @ApiProperty({ enum: ['ACTIVE', 'PENDING', 'REMOVED'], nullable: true })
  membershipStatus!: string | null;
}

export class CompanyForMeResponseDto {
  @ApiProperty({ type: () => CompanyInfoDto, nullable: true })
  company!: CompanyInfoDto | null;
  @ApiProperty({
    description:
      'True only for an Entra admin (Global or Privileged Role Administrator) whose organisation has no workspace yet.',
  })
  canStartTrial!: boolean;
}

export class CompanyTrialRequestDto {
  @ApiProperty({ maxLength: 120 }) displayName!: string;
}

export class SwitchWorkspaceRequestDto {
  @ApiProperty() tenantId!: string;
}

export class JoinRequestRespondDto {
  @ApiProperty() tenantId!: string;
  @ApiProperty({ enum: ['PENDING'] }) membershipStatus!: string;
}

export class JoinRequestDto {
  @ApiProperty() membershipId!: string;
  @ApiProperty({ nullable: true, type: String }) email!: string | null;
  @ApiProperty({ nullable: true, type: String }) displayName!: string | null;
  @ApiProperty({ format: 'date-time' }) requestedAt!: Date;
}

export class JoinRequestListResponseDto {
  @ApiProperty({ type: () => JoinRequestDto, isArray: true })
  items!: JoinRequestDto[];
}

export class DecideJoinRequestDto {
  @ApiProperty({
    enum: ROLES,
    required: false,
    description: 'Defaults to DEVELOPER (the member role).',
  })
  role?: string;
}

export class MeWorkspaceDto {
  @ApiProperty() id!: string;
  @ApiProperty() name!: string;
  @ApiProperty({ enum: ['PERSONAL', 'COMPANY', 'SAMPLE'] }) kind!: string;
}

export class MeResponseDto {
  @ApiProperty() subject!: string;
  @ApiProperty() email!: string;
  @ApiProperty() displayName!: string;
  @ApiProperty({ type: () => MeWorkspaceDto }) workspace!: MeWorkspaceDto;
  @ApiProperty({
    enum: ROLES,
    isArray: true,
    description: 'From the workspace Membership, never from the token.',
  })
  roles!: string[];
}
