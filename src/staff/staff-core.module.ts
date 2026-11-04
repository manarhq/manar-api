import { Module } from '@nestjs/common';
import { AuthorizationModule } from '../authorization/authorization.module';
import { StaffAuditService } from './audit/staff-audit.service';
import { StaffRbacService } from './rbac/staff-rbac.service';

/**
 * Staff RBAC and the staff audit chain, without HTTP: shared by the staff listener and the CLI.
 * Needs the global DatabaseModule (control DB, OpenBao) and AuditModule (CheckpointSigner).
 */
@Module({
  imports: [AuthorizationModule],
  providers: [StaffAuditService, StaffRbacService],
  exports: [StaffAuditService, StaffRbacService, AuthorizationModule],
})
export class StaffCoreModule {}
