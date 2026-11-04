import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import webpush from 'web-push';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { ApproverDirectory } from '../approvals/approver-directory';
import { isAllowedPushEndpoint } from './push-endpoint';
import { signPushAction } from '../phone/phone-token';

/**
 * What a push carries. Never a resource path, a prompt or a secret: the push service sees only the
 * (encrypted) payload, and the console shows the details after sign-in.
 */
export interface PushPayload {
  kind: 'approval' | 'approval_closed' | 'approval_revoked' | 'secret_alert';
  title: string;
  body: string;
  /** Console path to open, e.g. `/approvals`. */
  url: string;
  tag: string;
  /** The approval this push is about (an id, never its contents). */
  approvalId?: string;
  /**
   * Add Approve once / Deny buttons: each subscriber gets its own signed single-use token bound to
   * that person and workspace. Needs `approvalId` and `expiresAt`; never for high-risk approvals.
   */
  actionable?: boolean;
  /** Approval expiry, ms since epoch; the buttons stop working then. */
  expiresAt?: number;
}

export interface PushSubscriptionInput {
  endpoint: string;
  p256dh: string;
  auth: string;
}

export type PushSender = (
  subscription: { endpoint: string; keys: { p256dh: string; auth: string } },
  payload: string,
) => Promise<unknown>;

/** Test seam: provide a fake sender under this token. */
export const PUSH_SENDER = Symbol('PUSH_SENDER');

@Injectable()
export class PushService {
  private readonly logger = new Logger(PushService.name);
  private readonly sender: PushSender | null;
  readonly publicKey: string | null;
  private readonly signingSecret: string | undefined;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly approvers: ApproverDirectory,
    config: ConfigService<AppConfig, true>,
    @Optional() @Inject(PUSH_SENDER) sender?: PushSender,
  ) {
    const pub = config.get('VAPID_PUBLIC_KEY', { infer: true });
    const priv = config.get('VAPID_PRIVATE_KEY', { infer: true });
    const subject = config.get('VAPID_SUBJECT', { infer: true });
    this.signingSecret = config.get('APPROVAL_GRANT_SIGNING_SECRET', {
      infer: true,
    });
    this.publicKey = pub && priv && subject ? pub : null;
    if (sender) this.sender = sender;
    else if (pub && priv && subject) {
      const vapidDetails = { subject, publicKey: pub, privateKey: priv };
      this.sender = (s, p) =>
        webpush.sendNotification(s, p, { vapidDetails, TTL: 600 });
    } else this.sender = null;
  }

  get enabled(): boolean {
    return this.sender !== null;
  }

  async subscribe(
    subject: string,
    tenantId: string,
    sub: PushSubscriptionInput,
  ): Promise<void> {
    if (!this.enabled) throw new Error('push is not configured');
    if (!isAllowedPushEndpoint(sub.endpoint))
      throw new Error('not a browser push service');
    await this.control.pushSubscription.upsert({
      where: { endpoint: sub.endpoint },
      // The endpoint is a capability URL; re-subscribing from the same browser moves it to the
      // current person and workspace.
      update: { subject, tenantId, p256dh: sub.p256dh, auth: sub.auth },
      create: { subject, tenantId, ...sub },
    });
  }

  async unsubscribe(subject: string, endpoint: string): Promise<void> {
    await this.control.pushSubscription.deleteMany({
      where: { endpoint, subject },
    });
  }

  /** Sent to every approver of this workspace who has subscribed. Never throws. */
  async notifyApprovers(
    tenantClient: Pick<TenantPrismaClient, 'roleBinding'>,
    tenantId: string,
    payload: PushPayload,
  ): Promise<number> {
    if (!this.sender) return 0;
    try {
      const subjects = await this.approvers.listSubjects(
        tenantId,
        tenantClient,
      );
      if (subjects.length === 0) return 0;
      const subs = await this.control.pushSubscription.findMany({
        where: { tenantId, subject: { in: subjects } },
      });
      const { actionable, expiresAt, ...plain } = payload;
      const canAct =
        actionable && payload.approvalId && expiresAt && this.signingSecret;
      const bodyFor = (subject: string) =>
        JSON.stringify(
          canAct
            ? {
                ...plain,
                expiresAt,
                action: signPushAction(this.signingSecret, {
                  a: payload.approvalId!,
                  s: subject,
                  t: tenantId,
                  e: expiresAt,
                }).token,
              }
            : plain,
        );
      let sent = 0;
      await Promise.all(
        subs.map(async (s) => {
          try {
            // Re-checked on every send: a row written before the allow-list is never contacted.
            if (!isAllowedPushEndpoint(s.endpoint)) {
              await this.control.pushSubscription.deleteMany({
                where: { id: s.id },
              });
              return;
            }
            await this.sender!(
              {
                endpoint: s.endpoint,
                keys: { p256dh: s.p256dh, auth: s.auth },
              },
              bodyFor(s.subject),
            );
            sent += 1;
          } catch (error) {
            const status = (error as { statusCode?: number }).statusCode;
            if (status === 404 || status === 410) {
              await this.control.pushSubscription.deleteMany({
                where: { id: s.id },
              });
            } else {
              this.logger.warn(
                `push to one subscription failed (status ${status ?? 'unknown'})`,
              );
            }
          }
        }),
      );
      return sent;
    } catch (error) {
      this.logger.warn(
        `push fan-out failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return 0;
    }
  }

  /** For the secrets track: a secret was touched or a vault release was denied. */
  notifySecretAlert(
    tenantClient: Pick<TenantPrismaClient, 'roleBinding'>,
    tenantId: string,
    toolName: string,
  ): Promise<number> {
    return this.notifyApprovers(tenantClient, tenantId, {
      kind: 'secret_alert',
      title: 'WARDEN',
      body: `${toolName} touched a secret`,
      url: '/secrets',
      tag: 'secret-alert',
    });
  }
}
