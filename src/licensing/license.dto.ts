import { ApiProperty } from '@nestjs/swagger';
import {
  LICENSE_RESOURCES,
  LICENSE_STATUSES,
  type LicenseResource,
  type LicenseStatusName,
} from './license';

const nullableString = { nullable: true, type: String } as const;
const nullableInt = { nullable: true, type: Number } as const;

export class LicenseUsageDto {
  @ApiProperty(nullableInt) agents!: number | null;
  @ApiProperty(nullableInt) tenants!: number | null;
}

/** What a tenant admin needs for a banner: no customer name, no limits, no other tenant's counts. */
export class TenantLicenseDto {
  @ApiProperty({ enum: LICENSE_STATUSES }) status!: LicenseStatusName;
  @ApiProperty({ enum: ['hosted', 'customer'] })
  deployment!: 'hosted' | 'customer';
  @ApiProperty({ ...nullableString, format: 'date-time' })
  expiresAt!: string | null;
  @ApiProperty({
    ...nullableInt,
    description: 'Whole days to expiry; negative once expired',
  })
  daysLeft!: number | null;
  @ApiProperty({ description: 'True when any licensed amount is exceeded' })
  overLimit!: boolean;
}

/** `GET /platform/v1/license`: the full status. */
export class LicenseStatusDto {
  @ApiProperty({ enum: LICENSE_STATUSES }) status!: LicenseStatusName;
  @ApiProperty({
    ...nullableString,
    description: 'malformed, bad_signature, unknown_kid or file_unreadable',
  })
  reason!: string | null;
  @ApiProperty({ enum: ['hosted', 'customer'] })
  deployment!: 'hosted' | 'customer';
  @ApiProperty(nullableString) kid!: string | null;
  @ApiProperty(nullableString) licenseId!: string | null;
  @ApiProperty(nullableString) customer!: string | null;
  @ApiProperty({ ...nullableString, format: 'date-time' }) issuedAt!:
    string | null;
  @ApiProperty({ ...nullableString, format: 'date-time' }) notBefore!:
    string | null;
  @ApiProperty({ ...nullableString, format: 'date-time' }) expiresAt!:
    string | null;
  @ApiProperty(nullableInt) daysLeft!: number | null;
  @ApiProperty({
    type: LicenseUsageDto,
    nullable: true,
    description: 'null = unlimited',
  })
  limits!: LicenseUsageDto | null;
  @ApiProperty({ type: [String] }) features!: string[];
  @ApiProperty({ type: LicenseUsageDto }) usage!: LicenseUsageDto;
  @ApiProperty({ enum: LICENSE_RESOURCES, isArray: true })
  overLimit!: LicenseResource[];
  @ApiProperty({ format: 'date-time' }) checkedAt!: string;
}
