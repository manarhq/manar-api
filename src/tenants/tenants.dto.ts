import { ApiProperty } from '@nestjs/swagger';

/**
 * `GET /tenants/:slug/oidc-config`'s response — see `TenantsController`'s
 * doc comment for what this deliberately does and does not expose. Every
 * field here is safe for an unauthenticated caller (a pre-login browser,
 * or `manar-web`'s BFF) to see.
 */
export class TenantOidcConfigResponseDto {
  @ApiProperty({ format: 'uuid' })
  tenantId!: string;

  @ApiProperty({ example: 'acme-corp' })
  slug!: string;

  @ApiProperty({
    example: 'acme-corp',
    description: "The Keycloak realm name — equal to the tenant's slug.",
  })
  realm!: string;

  @ApiProperty({ example: 'http://localhost:8081/realms/acme-corp' })
  issuerUrl!: string;

  @ApiProperty({ example: 'manar-api' })
  clientId!: string;

  @ApiProperty({
    example:
      'http://localhost:8081/realms/acme-corp/protocol/openid-connect/auth',
  })
  authorizationEndpoint!: string;

  @ApiProperty({
    example:
      'http://localhost:8081/realms/acme-corp/protocol/openid-connect/token',
  })
  tokenEndpoint!: string;

  @ApiProperty({
    example:
      'http://localhost:8081/realms/acme-corp/protocol/openid-connect/logout',
  })
  endSessionEndpoint!: string;

  @ApiProperty({
    example:
      'http://localhost:8081/realms/acme-corp/protocol/openid-connect/certs',
  })
  jwksUri!: string;
}

/**
 * `GET /tenants/:slug/oidc-client-secret`'s response — gated by
 * `BffServiceGuard`, never by a tenant JWT (there is none yet at this
 * point in the login flow). See `TenantsController`'s doc comment for the
 * full security design.
 */
export class TenantOidcClientSecretResponseDto {
  @ApiProperty({
    description:
      "The confidential client's secret, in plaintext. Only ever returned to a caller presenting the X-Manar-Bff-Token service credential — never to an arbitrary/unauthenticated caller.",
  })
  clientSecret!: string;
}
