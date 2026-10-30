import { Inject, Injectable } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { generateSampleData } from './sample-data.generator';
import {
  SAMPLE_DIRECTORY,
  WORKSPACE_PROVISIONING,
  type SampleDirectory,
  type WorkspaceProvisioning,
} from './workspace-provisioning.port';

export interface SampleResult {
  tenantId: string;
  status: 'ACTIVE' | 'QUEUED';
}

/**
 * One SAMPLE workspace per user, created the first time they ask. It is a separate tenant, so
 * its rows live in its own database and audit chain and cannot reach the user's real workspace.
 * It does not count toward plan limits: limits are checked against the real workspace only.
 */
@Injectable()
export class SampleService {
  constructor(
    @Inject(WORKSPACE_PROVISIONING)
    private readonly provisioning: WorkspaceProvisioning,
    @Inject(SAMPLE_DIRECTORY) private readonly directory: SampleDirectory,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  async ensure(ownerSubject: string): Promise<SampleResult> {
    let tenantId = await this.directory.find(ownerSubject);
    let status: SampleResult['status'] = 'ACTIVE';
    if (!tenantId) {
      ({ tenantId, status } = await this.provisioning.createWorkspace({
        ownerSubject,
        kind: 'SAMPLE',
        displayName: 'Sample',
      }));
    }
    if (status === 'QUEUED') return { tenantId, status };
    let client;
    try {
      client = await this.tenantDatabaseManager.getClient(tenantId);
    } catch {
      return { tenantId, status: 'QUEUED' }; // database not ready yet; the next call fills it
    }
    if ((await client.host.count()) === 0) {
      await generateSampleData(client, this.audit, tenantId, ownerSubject);
    }
    return { tenantId, status: 'ACTIVE' };
  }

  async remove(ownerSubject: string): Promise<boolean> {
    const tenantId = await this.directory.find(ownerSubject);
    if (!tenantId) return false;
    await this.provisioning.deleteWorkspace(tenantId);
    return true;
  }
}
