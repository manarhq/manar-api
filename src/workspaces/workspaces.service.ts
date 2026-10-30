import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { authSetting } from '../auth/auth.config';
import { rolesOf, splitRoles } from '../auth/membership.service';
import type { RoleName } from '../auth/roles';
import type { VerifiedIdentity } from '../auth/token-verifier.service';
import type { AppConfig } from '../config/env.validation';
import { failClosed } from '../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  WorkspaceProvisioningService,
  type CreateWorkspaceResult,
} from './workspace-provisioning.service';

/** Microsoft's tenant for personal (consumer) accounts: not an organisation. */
export const CONSUMER_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad';
/** Entra directory role template ids carried in the `wids` claim. */
export const GLOBAL_ADMIN_WID = '62e90394-69f5-4237-9190-012177145e10';
export const PRIVILEGED_ROLE_ADMIN_WID = 'e8611ab8-c189-46e8-94e1-60213ab1f814';
/** What an approved joiner gets unless the admin picks another role. */
export const DEFAULT_MEMBER_ROLE: RoleName = 'DEVELOPER';

export type MembershipStatusName = 'ACTIVE' | 'PENDING' | 'REMOVED';

export interface WorkspaceSummary {
  tenantId: string;
  name: string;
  kind: 'PERSONAL' | 'COMPANY' | 'SAMPLE';
  /** Tenant lifecycle: ACTIVE means ready; QUEUED/PROVISIONING mean "Setting up your workspace". */
  status: string;
  membershipStatus: MembershipStatusName;
  roles: RoleName[];
}

export interface JoinRequestSummary {
  membershipId: string;
  email: string | null;
  displayName: string | null;
  requestedAt: Date;
}

/** A real organisation `tid`: present and not the consumer tenant. */
export function organisationTid(identity: VerifiedIdentity): string | null {
  const tid = identity.tid?.toLowerCase();
  return tid && tid !== CONSUMER_TENANT_ID ? tid : null;
}

export function isEntraAdmin(identity: VerifiedIdentity): boolean {
  return identity.wids.some(
    (w) => w === GLOBAL_ADMIN_WID || w === PRIVILEGED_ROLE_ADMIN_WID,
  );
}

/**
 * Workspace list, first sign-in, company discovery/trial and the request-to-join flow (spec 4.1,
 * 7a). Everything is keyed on the verified Keycloak `sub` (and `tid` for companies), never on an
 * email: two sign-in methods with one email are two subjects with two workspaces, and a matching
 * `tid` only ever lets a user ASK to join; an admin approves.
 */
@Injectable()
export class WorkspacesService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly provisioning: WorkspaceProvisioningService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async list(subject: string): Promise<WorkspaceSummary[]> {
    const rows = await failClosed('control-db', () =>
      this.control.membership.findMany({
        where: { subject, status: { in: ['ACTIVE', 'PENDING'] } },
        include: { tenant: true },
        orderBy: { createdAt: 'asc' },
      }),
    );
    return rows.map((m) => ({
      tenantId: m.tenantId,
      name: m.tenant.name,
      kind: m.tenant.kind,
      status: m.tenant.status,
      membershipStatus: m.status,
      // A pending joiner holds no roles yet.
      roles: m.status === 'ACTIVE' ? rolesOf(m) : [],
    }));
  }

  /** First sign-in: the caller's personal workspace, created once. Idempotent. */
  async ensurePersonal(
    identity: VerifiedIdentity,
  ): Promise<CreateWorkspaceResult> {
    const existing = await failClosed('control-db', () =>
      this.control.tenant.findFirst({
        where: { kind: 'PERSONAL', ownerSubject: identity.subject },
      }),
    );
    if (existing) {
      return {
        tenantId: existing.id,
        status: existing.status === 'ACTIVE' ? 'ACTIVE' : 'QUEUED',
      };
    }
    return this.provisioning.createWorkspace({
      ownerSubject: identity.subject,
      kind: 'PERSONAL',
      displayName: 'Personal workspace',
      ownerEmail: identity.email,
      ownerDisplayName: identity.displayName,
    });
  }

  /** The workspace the caller picked, if they hold an ACTIVE Membership for an ACTIVE tenant. */
  async assertSwitchable(
    subject: string,
    tenantId: string,
  ): Promise<WorkspaceSummary> {
    const found = (await this.list(subject)).find(
      (w) => w.tenantId === tenantId,
    );
    if (
      !found ||
      found.membershipStatus !== 'ACTIVE' ||
      found.status !== 'ACTIVE'
    ) {
      throw new ForbiddenException('Workspace not available');
    }
    return found;
  }

  /** "Join your company's workspace" discovery: only for a work account whose `tid` has one. */
  async companyForMe(identity: VerifiedIdentity) {
    const tid = organisationTid(identity);
    if (!tid) return { company: null, canStartTrial: false };
    const tenant = await failClosed('control-db', () =>
      this.control.tenant.findFirst({
        where: { kind: 'COMPANY', entraTenantId: tid },
      }),
    );
    if (!tenant) {
      return {
        company: null,
        canStartTrial: this.trialEnabled() && isEntraAdmin(identity),
      };
    }
    const membership = await this.control.membership.findUnique({
      where: {
        subject_tenantId: { subject: identity.subject, tenantId: tenant.id },
      },
    });
    return {
      company: {
        tenantId: tenant.id,
        name: tenant.name,
        membershipStatus: membership?.status ?? null,
      },
      canStartTrial: false,
    };
  }

  /**
   * Company trial (30 days, 25 devices: billing's entitlement). Only a work-account admin whose
   * token carries Global Administrator or Privileged Role Administrator in `wids`. One company
   * workspace per Entra tenant (409 otherwise: ask to join instead).
   */
  async startCompanyTrial(identity: VerifiedIdentity, displayName: string) {
    if (!this.trialEnabled()) {
      throw new ForbiddenException('company_trial_disabled');
    }
    const tid = organisationTid(identity);
    if (!tid) throw new ForbiddenException('work_account_required');
    if (!isEntraAdmin(identity))
      throw new ForbiddenException('entra_admin_required');
    return this.provisioning.createWorkspace({
      ownerSubject: identity.subject,
      kind: 'COMPANY',
      displayName,
      entraTenantId: tid,
      ownerEmail: identity.email,
      ownerDisplayName: identity.displayName,
    });
  }

  /** Never automatic: this only records a PENDING Membership with no roles in effect. */
  async requestToJoin(identity: VerifiedIdentity) {
    const tid = organisationTid(identity);
    if (!tid) throw new ForbiddenException('work_account_required');
    const tenant = await failClosed('control-db', () =>
      this.control.tenant.findFirst({
        where: { kind: 'COMPANY', entraTenantId: tid },
      }),
    );
    if (!tenant) throw new NotFoundException('no_company_workspace');
    const existing = await this.control.membership.findUnique({
      where: {
        subject_tenantId: { subject: identity.subject, tenantId: tenant.id },
      },
    });
    if (existing?.status === 'ACTIVE')
      throw new ConflictException('already_member');
    if (existing) {
      if (existing.status === 'REMOVED') {
        await this.control.membership.update({
          where: { id: existing.id },
          data: {
            status: 'PENDING',
            email: identity.email,
            displayName: identity.displayName,
          },
        });
      }
      return { tenantId: tenant.id, membershipStatus: 'PENDING' as const };
    }
    await this.control.membership.create({
      data: {
        subject: identity.subject,
        tenantId: tenant.id,
        role: DEFAULT_MEMBER_ROLE,
        extraRoles: [],
        status: 'PENDING',
        email: identity.email,
        displayName: identity.displayName,
      },
    });
    return { tenantId: tenant.id, membershipStatus: 'PENDING' as const };
  }

  async listJoinRequests(tenantId: string): Promise<JoinRequestSummary[]> {
    const rows = await this.control.membership.findMany({
      where: { tenantId, status: 'PENDING', tenant: { kind: 'COMPANY' } },
      orderBy: { createdAt: 'asc' },
    });
    return rows.map((m) => ({
      membershipId: m.id,
      email: m.email,
      displayName: m.displayName,
      requestedAt: m.createdAt,
    }));
  }

  /** Approve a PENDING request of THIS workspace. A role above the approver's own is refused by the controller. */
  async decideJoinRequest(
    tenantId: string,
    membershipId: string,
    decision: 'approve' | 'reject',
    approvedBy: string,
    role?: RoleName,
  ): Promise<void> {
    const m = await this.control.membership.findFirst({
      where: {
        id: membershipId,
        tenantId,
        status: 'PENDING',
        tenant: { kind: 'COMPANY' },
      },
    });
    if (!m) throw new NotFoundException('join_request_not_found');
    if (decision === 'reject') {
      await this.control.membership.update({
        where: { id: m.id },
        data: { status: 'REMOVED', grantedBy: approvedBy },
      });
      return;
    }
    const split = splitRoles([role ?? DEFAULT_MEMBER_ROLE]);
    if (!split) throw new BadRequestException('role_required');
    await this.control.membership.update({
      where: { id: m.id },
      data: {
        status: 'ACTIVE',
        role: split.role,
        extraRoles: split.extraRoles,
        grantedBy: approvedBy,
      },
    });
  }

  private trialEnabled(): boolean {
    return authSetting(this.config, 'COMPANY_TRIAL_ENABLED') === 'true';
  }
}
