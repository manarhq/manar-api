import { ApiProperty } from '@nestjs/swagger';

export class TenantSsoInfoDto {
  @ApiProperty()
  realm!: string;

  @ApiProperty()
  issuerUrl!: string;

  @ApiProperty()
  clientId!: string;

  @ApiProperty()
  authorizationEndpoint!: string;

  @ApiProperty()
  tokenEndpoint!: string;

  @ApiProperty()
  endSessionEndpoint!: string;

  @ApiProperty()
  jwksUri!: string;
}

export class TenantAiProviderInfoDto {
  @ApiProperty({
    enum: ['anthropic', 'azure_openai', 'ollama', 'vllm', 'undeclared'],
    description:
      "Which provider manar-ai is currently configured to use for this deployment (AI_ADVISORY_PROVIDER, manar-api-side config -- see AiAdvisoryConfigSchema's doc comment for why manar-api cannot ask manar-ai this directly). Deployment-wide, not per-tenant.",
  })
  provider!: 'anthropic' | 'azure_openai' | 'ollama' | 'vllm' | 'undeclared';

  @ApiProperty({
    description:
      'Whether this provider is treated as leaving this deployment\'s own infrastructure -- true for everything except the self-hosted "ollama" and "vllm" (production with no provider declared counts as external). Governs whether this tenant\'s allowExternalAi flag has any effect.',
  })
  isExternal!: boolean;
}

export class TenantRateLimitInfoDto {
  @ApiProperty({
    description: 'Read-only: deployment-wide, not per-tenant-adjustable.',
  })
  humanRequestLimit!: number;

  @ApiProperty({
    description: 'Read-only: deployment-wide, not per-tenant-adjustable.',
  })
  humanWindowMs!: number;
}

/** `GET`/`PATCH /tenant/settings`'s response shape. */
export class TenantSettingsResponseDto {
  @ApiProperty({ format: 'uuid' })
  tenantId!: string;

  @ApiProperty()
  slug!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty({ enum: ['UAE', 'CUSTOM_REGION', 'AIR_GAPPED'] })
  residency!: string;

  @ApiProperty({
    description:
      "Whether this tenant's AI-advisory-eligible requests may reach an external AI provider. Takes effect immediately -- AiAdvisoryClient reads this tenant row live on every call, no caching.",
  })
  allowExternalAi!: boolean;

  @ApiProperty()
  allowOutboundTelemetry!: boolean;

  @ApiProperty()
  allowCloudStorage!: boolean;

  @ApiProperty({
    description:
      'Company workspaces: when true only approver roles decide approvals; a device owner or agent creator can no longer decide their own. Always false for a personal workspace.',
  })
  approvalsAdminsOnly!: boolean;

  @ApiProperty({
    description:
      'True once, after `ai:default-on` switched AI on for this workspace, until an owner or admin dismisses the console notice.',
  })
  aiDefaultNoticePending!: boolean;

  @ApiProperty({
    description:
      'True when AI is off and `ai:default-on` could not prove from the audit history that nobody chose that: the console asks "Turn on AI features?". Cleared by dismissing or by any change to allowExternalAi.',
  })
  aiOptInNoticePending!: boolean;

  @ApiProperty({ format: 'date-time' })
  updatedAt!: Date;

  @ApiProperty({
    type: () => TenantSsoInfoDto,
    nullable: true,
    description:
      "Read-only display of this tenant's Keycloak realm/issuer info (Phase 11b's GET /tenants/:slug/oidc-config, mirrored here for a same-request authenticated view). SSO federation configuration itself lives in Keycloak's own admin console -- null if this tenant has no provisioned realm yet.",
  })
  sso!: TenantSsoInfoDto | null;

  @ApiProperty({ type: () => TenantAiProviderInfoDto })
  aiProvider!: TenantAiProviderInfoDto;

  @ApiProperty({ type: () => TenantRateLimitInfoDto })
  rateLimit!: TenantRateLimitInfoDto;
}

export class UpdateTenantSettingsRequestDto {
  @ApiProperty({
    enum: ['UAE', 'CUSTOM_REGION', 'AIR_GAPPED'],
    required: false,
  })
  residency?: string;

  @ApiProperty({ required: false })
  allowExternalAi?: boolean;

  @ApiProperty({ required: false })
  allowOutboundTelemetry?: boolean;

  @ApiProperty({ required: false })
  allowCloudStorage?: boolean;

  @ApiProperty({ required: false, description: 'Company workspaces only.' })
  approvalsAdminsOnly?: boolean;
}
