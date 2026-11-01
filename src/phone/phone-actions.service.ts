import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApproverDirectory } from '../approvals/approver-directory';
import { HostApprovalsService } from '../approvals/host-approvals.service';
import type { AuthContext } from '../auth/auth-context';
import type { AppConfig } from '../config/env.validation';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { verifyPushAction } from './phone-token';

/**
 * Approve once / Deny pressed in a notification. The browser sends the token it was pushed (end to
 * end encrypted to that browser) together with its signed-in session; both must agree.
 */
@Injectable()
export class PhoneActionsService {
  private readonly secret: string;

  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly approvers: ApproverDirectory,
    private readonly approvals: HostApprovalsService,
    config: ConfigService<AppConfig, true>,
  ) {
    this.secret = config.get('APPROVAL_GRANT_SIGNING_SECRET', { infer: true });
  }

  async decideFromPush(
    auth: AuthContext,
    token: string,
    decision: 'approve_once' | 'deny',
    now = new Date(),
  ) {
    const claims = verifyPushAction(this.secret, token, now.getTime());
    // Same person, same workspace as the one the push was minted for.
    if (
      !claims ||
      claims.s !== auth.user.keycloakSubject ||
      claims.t !== auth.tenant.id
    )
      throw new UnauthorizedException('invalid_action');
    const client = await this.tenants.getClient(auth.tenant.id);
    if (
      !(await this.approvers.canApprove(
        auth.tenant.id,
        client,
        auth.user.keycloakSubject,
      ))
    )
      throw new ForbiddenException('not_an_approver');
    const row = await this.approvals.get(client, claims.a);
    if (row.highRisk) throw new ForbiddenException('high_risk_open_in_console');
    const result = await this.approvals.decide(client, auth.tenant.id, {
      approvalId: claims.a,
      subject: auth.user.keycloakSubject,
      decision,
      via: 'push',
      // Single use: spent in the same transaction as the decision, after every check above, so a
      // refused press never burns the token and an accepted one cannot be replayed.
      nonce: { value: claims.n, expiresAt: new Date(claims.e) },
    });
    void client.phoneActionUse
      .deleteMany({ where: { expiresAt: { lt: now } } })
      .catch(() => undefined);
    return result;
  }
}
