import { ApiProperty } from '@nestjs/swagger';
import { AuditEventProofDto, CheckpointPublicKeyDto } from '../audit/audit.dto';

/** Mirrors `EvidenceExportRequestSchema` (`evidence-export.validation.ts`). At least one filter dimension is required. */
export class EvidenceExportRequestDto {
  @ApiProperty({ required: false, format: 'date-time' })
  since?: Date;

  @ApiProperty({ required: false, format: 'date-time' })
  until?: Date;

  @ApiProperty({ required: false, format: 'uuid' })
  agentId?: string;

  @ApiProperty({ required: false, format: 'uuid' })
  taskId?: string;

  @ApiProperty({ required: false, format: 'uuid' })
  correlationId?: string;
}

class EvidenceFilterDto {
  @ApiProperty({ nullable: true, type: String, format: 'date-time' })
  since!: string | null;

  @ApiProperty({ nullable: true, type: String, format: 'date-time' })
  until!: string | null;

  @ApiProperty({ nullable: true, type: String })
  agentId!: string | null;

  @ApiProperty({ nullable: true, type: String })
  taskId!: string | null;

  @ApiProperty({ nullable: true, type: String })
  correlationId!: string | null;
}

class EvidenceEventDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  sequence!: number;

  @ApiProperty()
  eventType!: string;

  @ApiProperty({ format: 'uuid' })
  correlationId!: string;

  @ApiProperty({ type: 'object', additionalProperties: true })
  actor!: unknown;

  @ApiProperty({ format: 'date-time' })
  timestamp!: string;

  @ApiProperty({ type: 'object', additionalProperties: true })
  data!: unknown;

  @ApiProperty({ nullable: true, type: String })
  previousHash!: string | null;

  @ApiProperty()
  eventHash!: string;

  @ApiProperty({ minimum: 0, maximum: 63 })
  partition!: number;

  @ApiProperty({ description: 'Decimal string.' })
  partitionSeq!: string;

  @ApiProperty({
    type: () => AuditEventProofDto,
    nullable: true,
    description:
      'Inclusion proof against a signed checkpoint; null until one covers the event.',
  })
  proof!: AuditEventProofDto | null;
}

class EvidenceCertificateDto {
  @ApiProperty()
  serialNumber!: string;

  @ApiProperty()
  subject!: string;

  @ApiProperty({ format: 'date-time' })
  notBefore!: string;

  @ApiProperty({ format: 'date-time' })
  notAfter!: string;

  @ApiProperty({ nullable: true, type: String, format: 'date-time' })
  revokedAt!: string | null;

  @ApiProperty({ nullable: true, type: String })
  revocationReason!: string | null;
}

class EvidenceAgentDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  slug!: string;

  @ApiProperty()
  identifier!: string;

  @ApiProperty()
  displayName!: string;

  @ApiProperty({ enum: ['PENDING_ENROLLMENT', 'ACTIVE', 'REVOKED', 'KILLED'] })
  status!: string;

  @ApiProperty({ type: () => EvidenceCertificateDto, isArray: true })
  certificates!: EvidenceCertificateDto[];
}

class EvidenceTaskDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty({ format: 'uuid' })
  requesterId!: string;

  @ApiProperty({ format: 'uuid' })
  assignedAgentId!: string;

  @ApiProperty({ nullable: true, type: String, format: 'uuid' })
  parentTaskId!: string | null;

  @ApiProperty({
    enum: ['PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'COMPLETED'],
  })
  status!: string;

  @ApiProperty()
  riskCeiling!: number;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: string;

  @ApiProperty({ format: 'date-time' })
  createdAt!: string;
}

class EvidenceTaskDelegationDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  parentTaskId!: string;

  @ApiProperty({ format: 'uuid' })
  childTaskId!: string;

  @ApiProperty({ format: 'date-time' })
  createdAt!: string;
}

class EvidencePolicyVersionDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  policyId!: string;

  @ApiProperty()
  policyName!: string;

  @ApiProperty()
  version!: number;

  @ApiProperty({ enum: ['DRAFT', 'PUBLISHED'] })
  status!: string;

  @ApiProperty()
  contentHash!: string;

  @ApiProperty({ nullable: true, type: String, format: 'date-time' })
  publishedAt!: string | null;
}

class EvidenceApprovalRequestDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  taskId!: string;

  @ApiProperty({ format: 'uuid' })
  agentId!: string;

  @ApiProperty()
  toolId!: string;

  @ApiProperty()
  actionId!: string;

  @ApiProperty()
  resource!: string;

  @ApiProperty()
  riskScore!: number;

  @ApiProperty({ enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED'] })
  status!: string;

  @ApiProperty({ format: 'date-time' })
  requestedAt!: string;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: string;
}

class EvidenceApprovalDecisionDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  approvalRequestId!: string;

  @ApiProperty({ format: 'uuid' })
  approverId!: string;

  @ApiProperty({ enum: ['APPROVE', 'DENY'] })
  decision!: string;

  @ApiProperty({ nullable: true, type: String })
  reason!: string | null;

  @ApiProperty({ format: 'date-time' })
  decidedAt!: string;
}

class EvidenceAuthorizationGrantDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  approvalRequestId!: string;

  @ApiProperty({ format: 'uuid' })
  taskId!: string;

  @ApiProperty({ format: 'uuid' })
  agentId!: string;

  @ApiProperty()
  toolId!: string;

  @ApiProperty()
  actionId!: string;

  @ApiProperty()
  riskScore!: number;

  @ApiProperty({ format: 'date-time' })
  issuedAt!: string;

  @ApiProperty({ format: 'date-time' })
  expiresAt!: string;

  @ApiProperty({ nullable: true, type: String, format: 'date-time' })
  consumedAt!: string | null;
}

class EvidenceToolInvocationDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ format: 'uuid' })
  taskId!: string;

  @ApiProperty({ format: 'uuid' })
  agentId!: string;

  @ApiProperty()
  toolId!: string;

  @ApiProperty()
  actionId!: string;

  @ApiProperty()
  resource!: string;

  @ApiProperty()
  status!: string;

  @ApiProperty({ format: 'date-time' })
  startedAt!: string;

  @ApiProperty({ nullable: true, type: String, format: 'date-time' })
  completedAt!: string | null;

  @ApiProperty({ nullable: true, type: String })
  errorMessage!: string | null;
}

class EvidenceContextDto {
  @ApiProperty({ type: () => EvidenceAgentDto, isArray: true })
  agents!: EvidenceAgentDto[];

  @ApiProperty({ type: () => EvidenceTaskDto, isArray: true })
  tasks!: EvidenceTaskDto[];

  @ApiProperty({ type: () => EvidenceTaskDelegationDto, isArray: true })
  taskDelegations!: EvidenceTaskDelegationDto[];

  @ApiProperty({ type: () => EvidencePolicyVersionDto, isArray: true })
  policyVersions!: EvidencePolicyVersionDto[];

  @ApiProperty({ type: () => EvidenceApprovalRequestDto, isArray: true })
  approvalRequests!: EvidenceApprovalRequestDto[];

  @ApiProperty({ type: () => EvidenceApprovalDecisionDto, isArray: true })
  approvalDecisions!: EvidenceApprovalDecisionDto[];

  @ApiProperty({ type: () => EvidenceAuthorizationGrantDto, isArray: true })
  authorizationGrants!: EvidenceAuthorizationGrantDto[];

  @ApiProperty({ type: () => EvidenceToolInvocationDto, isArray: true })
  toolInvocations!: EvidenceToolInvocationDto[];
}

class EvidenceBundleDto {
  @ApiProperty({ format: 'uuid' })
  tenantId!: string;

  @ApiProperty({ format: 'uuid' })
  exportId!: string;

  @ApiProperty({ format: 'uuid' })
  exportedBy!: string;

  @ApiProperty({ format: 'date-time' })
  generatedAt!: string;

  @ApiProperty({ type: () => EvidenceFilterDto })
  filter!: EvidenceFilterDto;

  @ApiProperty({ type: () => EvidenceEventDto, isArray: true })
  events!: EvidenceEventDto[];

  @ApiProperty({ type: () => EvidenceContextDto })
  context!: EvidenceContextDto;

  @ApiProperty({ type: () => CheckpointPublicKeyDto })
  checkpointPublicKey!: CheckpointPublicKeyDto;
}

class EvidenceBundleSignatureDto {
  @ApiProperty({ description: 'sha256 hex of canonicalize(bundle).' })
  bundleHash!: string;

  @ApiProperty({
    description:
      'A compact HS256 JWT over { bundleHash } — the signature artifact a recipient verifies.',
  })
  signature!: string;

  @ApiProperty({ enum: ['HS256'] })
  algorithm!: 'HS256';
}

/** Mirrors `EvidenceExportResult` (`evidence-export.service.ts`) — `EvidenceExportController.export`'s actual response. */
export class EvidenceExportResponseDto {
  @ApiProperty({ format: 'uuid' })
  exportId!: string;

  @ApiProperty({ type: () => EvidenceBundleDto })
  bundle!: EvidenceBundleDto;

  @ApiProperty({ type: () => EvidenceBundleSignatureDto })
  signature!: EvidenceBundleSignatureDto;
}
