import { Injectable, Logger } from '@nestjs/common';
import { ApproverDirectory } from '../approvals/approver-directory';
import { HostApprovalsService } from '../approvals/host-approvals.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { verifyTelegramCallback } from '../phone/phone-token';
import { RateWindow } from '../phone/rate-window';
import { tgLocale, tgText } from './telegram.messages';
import { TelegramService } from './telegram.service';

interface Chat {
  id: number;
  type: string;
}
export interface TelegramUpdate {
  message?: {
    chat?: Chat;
    from?: { id?: number; language_code?: string };
    text?: string;
  };
  callback_query?: {
    id: string;
    from?: { id?: number };
    data?: string;
    message?: { chat?: Chat };
  };
}

/** What the webhook does with an update. Everything here is untrusted input from the network. */
@Injectable()
export class TelegramBotHandler {
  private readonly logger = new Logger(TelegramBotHandler.name);
  private readonly perChat = new RateWindow(30, 60_000);
  private readonly badCodes = new RateWindow(5, 10 * 60_000);

  constructor(
    private readonly telegram: TelegramService,
    private readonly tenants: TenantDatabaseManager,
    private readonly approvers: ApproverDirectory,
    private readonly approvals: HostApprovalsService,
    private readonly audit: AuditService,
  ) {}

  async handle(update: TelegramUpdate): Promise<void> {
    try {
      if (update.callback_query) await this.onCallback(update.callback_query);
      else if (update.message) await this.onMessage(update.message);
    } catch (error) {
      // No update content in the log: it can hold a link code.
      this.logger.warn(
        `update failed: ${error instanceof Error ? error.message : 'error'}`,
      );
    }
  }

  private async onMessage(m: NonNullable<TelegramUpdate['message']>) {
    // Private chats only: a group must never become an approver.
    if (!m.chat || m.chat.type !== 'private' || typeof m.text !== 'string')
      return;
    const chatId = String(m.chat.id);
    const locale = tgLocale(m.from?.language_code);
    const t = tgText(locale);
    // Limits are per Telegram chat and user, checked after the webhook secret (the route's own
    // limit per address is only a generous global cap).
    if (
      !this.perChat.allow(chatId) ||
      !this.perChat.allow(`u${m.from?.id ?? ''}`)
    )
      return;
    const [cmd, ...rest] = m.text.trim().split(/\s+/);
    const command = cmd?.split('@')[0]?.toLowerCase();
    if (command === '/stop' || command === '/unlink') {
      const link = await this.telegram.findLink(chatId);
      if (link && (await this.telegram.unlinkChat(chatId))) {
        await this.auditLink(link.tenantId, link.subject, 'removed');
      }
      return this.telegram.say(chatId, t.unlinked);
    }
    if (command !== '/start' || rest.length === 0)
      return this.telegram.say(chatId, t.help);
    if (!this.badCodes.allow(chatId))
      return this.telegram.say(chatId, t.tooMany);
    const code = await this.telegram.consumeLinkCode(rest.join(''));
    if (!code) return this.telegram.say(chatId, t.badCode);
    const client = await this.tenants.getClient(code.tenantId);
    if (!(await this.approvers.canApprove(code.tenantId, client, code.subject)))
      return this.telegram.say(chatId, t.badCode);
    const linked = await this.telegram.link(
      code.tenantId,
      code.subject,
      chatId,
      locale,
    );
    // The chat belongs to someone else: they must /stop first (the code is spent either way).
    if (!linked) return this.telegram.say(chatId, t.linkedElsewhere);
    await this.auditLink(code.tenantId, code.subject, 'created');
    const workspace = await this.telegram.workspaceName(code.tenantId);
    await this.telegram.say(chatId, t.linked(workspace));
    // Tell the person's other chats that one was added.
    for (const o of linked.others)
      await this.telegram.say(o.chatId, tgText(o.locale).relinked(workspace));
  }

  private async onCallback(q: NonNullable<TelegramUpdate['callback_query']>) {
    const chat = q.message?.chat;
    if (!chat || chat.type !== 'private' || typeof q.data !== 'string') return;
    const chatId = String(chat.id);
    const answer = (text: string) =>
      this.telegram
        .call('answerCallbackQuery', {
          callback_query_id: q.id,
          text,
          show_alert: false,
        })
        .catch(() => undefined);
    const link = await this.telegram.findLink(chatId);
    if (
      !this.perChat.allow(chatId) ||
      !this.perChat.allow(`u${q.from?.id ?? ''}`)
    )
      return void (await answer(tgText(link?.locale).tooMany));
    const t = tgText(link?.locale);
    // The signature binds the approval, the choice and this chat.
    if (!link) return void (await answer(t.notLinked));
    const v = verifyTelegramCallback(this.telegram.callbackSecret, q.data, {
      chatId,
      tenantId: link.tenantId,
      subject: link.subject,
    });
    if (!v) return void (await answer(t.gone));
    const client = await this.tenants.getClient(link.tenantId);
    if (!(await this.approvers.canApprove(link.tenantId, client, link.subject)))
      return void (await answer(t.notApprover));
    const row = await this.approvals
      .get(client, v.approvalId)
      .catch(() => null);
    if (!row) return void (await answer(t.gone));
    if (row.highRisk) return void (await answer(t.openConsole));
    try {
      const r = await this.approvals.decide(client, link.tenantId, {
        approvalId: v.approvalId,
        subject: link.subject,
        decision: v.choice === 'y' ? 'approve_once' : 'deny',
        via: 'telegram',
      });
      await answer(t.outcome[r.decision]);
    } catch {
      // Already decided or timed out: the message is closed by the decide path or the sweeper.
      await answer(t.gone);
      const now = await this.approvals
        .get(client, v.approvalId)
        .catch(() => null);
      if (now && now.status !== 'PENDING')
        await this.telegram.closeApproval(
          link.tenantId,
          v.approvalId,
          now.status === 'DENIED'
            ? 'deny'
            : now.status === 'APPROVED'
              ? now.decision === 'approve_8h'
                ? 'approve_8h'
                : 'approve_once'
              : 'expired',
        );
      // Still pending and expired: the sweeper closes it.
    }
  }

  private async auditLink(
    tenantId: string,
    subject: string,
    what: 'created' | 'removed',
  ) {
    const client = await this.tenants.getClient(tenantId);
    await this.audit.recordSafely(client, tenantId, {
      eventType:
        what === 'created'
          ? AUDIT_EVENT_TYPES.TELEGRAM_LINK_CREATED
          : AUDIT_EVENT_TYPES.TELEGRAM_LINK_REMOVED,
      actor: { type: 'human', id: subject },
      data: {},
    });
  }
}
