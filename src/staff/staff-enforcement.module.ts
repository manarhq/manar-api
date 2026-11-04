import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import {
  STAFF_AUDIT_CHAIN_ID,
  StaffAuditService,
} from './audit/staff-audit.service';
import { ResignupService } from './restrictions/resignup.service';

/**
 * The customer-side half of DESK restrictions, in the human app: the re-signup checks at
 * workspace creation, device registration and Stripe card events (spec §9.5). The restriction
 * lookup itself (RestrictionEnforcement) is provided with the token verifier in AuthModule.
 */
@Global()
@Module({
  providers: [
    {
      provide: STAFF_AUDIT_CHAIN_ID,
      useFactory: (c: ConfigService<AppConfig, true>): string =>
        c.get('STAFF_AUDIT_CHAIN_ID', { infer: true }),
      inject: [ConfigService],
    },
    StaffAuditService,
    ResignupService,
  ],
  exports: [ResignupService],
})
export class StaffEnforcementModule {}
