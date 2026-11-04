import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { AuthorizationModule } from '../authorization/authorization.module';
import {
  STAFF_AUDIT_CHAIN_ID,
  StaffAuditService,
} from './audit/staff-audit.service';
import { StaffRbacService } from './rbac/staff-rbac.service';

/**
 * Staff RBAC and the staff audit chain, without HTTP: shared by the staff listener and the CLI.
 * Needs the global DatabaseModule (control DB, OpenBao) and AuditModule (CheckpointSigner).
 */
@Module({
  imports: [AuthorizationModule],
  providers: [
    {
      provide: STAFF_AUDIT_CHAIN_ID,
      useFactory: (c: ConfigService<AppConfig, true>): string =>
        c.get('STAFF_AUDIT_CHAIN_ID', { infer: true }),
      inject: [ConfigService],
    },
    StaffAuditService,
    StaffRbacService,
  ],
  exports: [StaffAuditService, StaffRbacService, AuthorizationModule],
})
export class StaffCoreModule {}
