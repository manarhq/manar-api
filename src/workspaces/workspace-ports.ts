/**
 * The interfaces other tracks consume (launch BRIEF section 2; the features track's sample
 * workspace). Import the tokens from here: a Symbol is only equal to itself, so there must be
 * exactly one definition.
 */
export type TenantKind = 'PERSONAL' | 'COMPANY' | 'SAMPLE';

export interface WorkspaceProvisioning {
  createWorkspace(input: {
    ownerSubject: string;
    kind: TenantKind;
    displayName: string;
  }): Promise<{ tenantId: string; status: 'ACTIVE' | 'QUEUED' }>;
  /**
   * Drops the tenant database and every control-DB row of a SAMPLE workspace. Refuses any other
   * kind (account deletion is a separate, graced flow).
   */
  deleteWorkspace(tenantId: string): Promise<void>;
}

export interface SampleDirectory {
  /** The SAMPLE workspace this user owns, if any. */
  find(ownerSubject: string): Promise<string | null>;
}

export const WORKSPACE_PROVISIONING = Symbol('WORKSPACE_PROVISIONING');
export const SAMPLE_DIRECTORY = Symbol('SAMPLE_DIRECTORY');
