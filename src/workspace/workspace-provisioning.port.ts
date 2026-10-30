import { ServiceUnavailableException } from '@nestjs/common';

/**
 * The interface the `identity` track builds (launch BRIEF section 2). Code here is written
 * against it; until that track is on main the providers below answer 503 `sample_unavailable`.
 * When it lands, bind WORKSPACE_PROVISIONING to `WorkspaceProvisioningService` (useExisting) and
 * SAMPLE_DIRECTORY to a lookup of `Tenant.kind = SAMPLE` joined to the user's ACTIVE Membership.
 */
export type TenantKind = 'PERSONAL' | 'COMPANY' | 'SAMPLE';

export interface WorkspaceProvisioning {
  createWorkspace(input: {
    ownerSubject: string;
    kind: TenantKind;
    displayName: string;
  }): Promise<{ tenantId: string; status: 'ACTIVE' | 'QUEUED' }>;
  /** Not in the BRIEF: DELETE /workspace/sample needs it from identity. */
  deleteWorkspace(tenantId: string): Promise<void>;
}

export interface SampleDirectory {
  /** The SAMPLE workspace this user owns, if any. */
  find(ownerSubject: string): Promise<string | null>;
}

export const WORKSPACE_PROVISIONING = Symbol('WORKSPACE_PROVISIONING');
export const SAMPLE_DIRECTORY = Symbol('SAMPLE_DIRECTORY');

const unavailable = () =>
  new ServiceUnavailableException({
    code: 'sample_unavailable',
    message: 'Sample data is not available yet.',
  });

export const stubProvisioning: WorkspaceProvisioning = {
  createWorkspace: () => Promise.reject(unavailable()),
  deleteWorkspace: () => Promise.reject(unavailable()),
};
export const stubDirectory: SampleDirectory = {
  find: () => Promise.resolve(null),
};
