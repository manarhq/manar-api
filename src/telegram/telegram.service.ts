import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, randomInt, timingSafeEqual } from 'node:crypto';
import { ApproverDirectory } from '../approvals/approver-directory';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { linkCodeHash, signTelegramCallback } from '../phone/phone-token';
import { RateWindow } from '../phone/rate-window';
import { tgText, type Outcome } from './telegram.messages';

/** Test seam for the HTTP call. */
export const TELEGRAM_FETCH = Symbol('TELEGRAM_FETCH');
type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export const LINK_CODE_TTL_MS = 10 * 60 * 1000;
export const MAX_LINKS_PER_PERSON = 3;
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

export interface ApprovalMessageInput {
  approvalId: string;
  toolName: string;
  /** The action type (e.g. file.write). Never the resource. */
  actionId: string;
  matchCode: string;
  highRisk: boolean;
  expiresAt: Date;
}

@Injectable()
export class TelegramService {
  private readonly logger = new Logger(TelegramService.name);
  private readonly token: string | undefined;
  private readonly webhookSecret: string | undefined;
  private readonly signingSecret: string;
  private readonly fetchImpl: FetchLike;
  readonly botUsername: string | undefined;
  readonly webhookUrl: string | undefined;
  /** At most 10 approval messages a minute to one chat; a flood stays in the console. */
  private readonly outbound = new RateWindow(10, 60_000);
  private readonly codesMade = new RateWindow(5, 60 * 60_000);
  private timer: NodeJS.Timeout | undefined;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly approvers: ApproverDirectory,
    config: ConfigService<AppConfig, true>,
    @Optional() @Inject(TELEGRAM_FETCH) fetchImpl?: FetchLike,
  ) {
    this.token = config.get('TELEGRAM_BOT_TOKEN', { infer: true });
    this.webhookSecret = config.get('TELEGRAM_WEBHOOK_SECRET', { infer: true });
    this.botUsername = config.get('TELEGRAM_BOT_USERNAME', { infer: true });
    this.webhookUrl = config.get('TELEGRAM_WEBHOOK_URL', { infer: true });
    this.signingSecret = config.get('APPROVAL_GRANT_SIGNING_SECRET', {
      infer: true,
    });
    this.fetchImpl = fetchImpl ?? ((u, i) => fetch(u, i));
  }

  get enabled(): boolean {
    return Boolean(this.token && this.webhookSecret && this.botUsername);
  }

  get callbackSecret(): string {
    return this.signingSecret;
  }

  hashCode(code: string): string {
    return linkCodeHash(this.signingSecret, code);
  }

  /** Constant-time check of Telegram's `X-Telegram-Bot-Api-Secret-Token` header. */
  verifyWebhookSecret(header: unknown): boolean {
    if (!this.webhookSecret || typeof header !== 'string') return false;
    const a = createHash('sha256').update(header).digest();
    const b = createHash('sha256').update(this.webhookSecret).digest();
    return timingSafeEqual(a, b);
  }

  /** Bot API call. The URL carries the token, so it is never logged; errors name the method only. */
  async call<T = unknown>(
    method: string,
    body: Record<string, unknown>,
  ): Promise<T> {
    if (!this.token) throw new Error('telegram is not configured');
    const res = await this.fetchImpl(
      `https://api.telegram.org/bot${this.token}/${method}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!res.ok) throw new Error(`telegram ${method} failed (${res.status})`);
    const json = (await res.json()) as { ok: boolean; result: T };
    if (!json.ok) throw new Error(`telegram ${method} refused`);
    return json.result;
  }

  /** Registers the webhook with Telegram (idempotent). Never throws. */
  async registerWebhook(): Promise<void> {
    if (!this.enabled || !this.webhookUrl) return;
    try {
      await this.call('setWebhook', {
        url: this.webhookUrl,
        secret_token: this.webhookSecret,
        allowed_updates: ['message', 'callback_query'],
        drop_pending_updates: false,
      });
    } catch (error) {
      this.logger.warn(
        `could not register the webhook: ${error instanceof Error ? error.message : 'error'}`,
      );
    }
  }

  // --- link flow ---------------------------------------------------------------------------

  /** A one-time code for the signed-in person; any older unused code of theirs is dropped. */
  async createLinkCode(tenantId: string, subject: string, now = new Date()) {
    if (!this.enabled) throw new Error('telegram is not configured');
    if (!this.codesMade.allow(`${tenantId}:${subject}`))
      throw new Error('too many codes');
    let code = '';
    for (let i = 0; i < 8; i += 1)
      code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
    const expiresAt = new Date(now.getTime() + LINK_CODE_TTL_MS);
    await this.control.$transaction([
      this.control.telegramLinkCode.deleteMany({
        where: { tenantId, subject },
      }),
      this.control.telegramLinkCode.create({
        data: { codeHash: this.hashCode(code), tenantId, subject, expiresAt },
      }),
    ]);
    return {
      code: `${code.slice(0, 4)}-${code.slice(4)}`,
      url: `https://t.me/${this.botUsername}?start=${code}`,
      expiresAt,
    };
  }

  /** Spends a code once. Null when unknown, expired or already used. */
  async consumeLinkCode(code: string, now = new Date()) {
    const codeHash = this.hashCode(code);
    const row = await this.control.telegramLinkCode.findUnique({
      where: { codeHash },
    });
    if (!row || row.expiresAt <= now) return null;
    const spent = await this.control.telegramLinkCode.deleteMany({
      where: { codeHash },
    });
    return spent.count === 1 ? row : null;
  }

  /**
   * Links the chat. Refused (null) when the chat already belongs to another person or workspace:
   * that person must `/stop` first. Otherwise returns the person's other chats, so they can be told.
   */
  async link(
    tenantId: string,
    subject: string,
    chatId: string,
    locale: string,
  ): Promise<{ others: { chatId: string; locale: string }[] } | null> {
    const existing = await this.control.telegramLink.findUnique({
      where: { chatId },
    });
    if (
      existing &&
      (existing.tenantId !== tenantId || existing.subject !== subject)
    )
      return null;
    await this.control.telegramLink.upsert({
      where: { chatId },
      update: { locale },
      create: { tenantId, subject, chatId, locale },
    });
    const mine = await this.control.telegramLink.findMany({
      where: { tenantId, subject },
      orderBy: { createdAt: 'desc' },
    });
    const extra = mine.slice(MAX_LINKS_PER_PERSON).map((m) => m.id);
    if (extra.length)
      await this.control.telegramLink.deleteMany({
        where: { id: { in: extra } },
      });
    return {
      others: mine
        .slice(0, MAX_LINKS_PER_PERSON)
        .filter((m) => m.chatId !== chatId),
    };
  }

  async workspaceName(tenantId: string): Promise<string> {
    const t = await this.control.tenant.findUnique({
      where: { id: tenantId },
      select: { name: true },
    });
    return t?.name ?? '';
  }

  async linksFor(tenantId: string, subject: string) {
    return this.control.telegramLink.findMany({
      where: { tenantId, subject },
      select: { createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  /** Console unlink: removes every chat of this person and tells each chat. */
  async unlinkPerson(tenantId: string, subject: string): Promise<number> {
    const rows = await this.control.telegramLink.findMany({
      where: { tenantId, subject },
    });
    if (rows.length === 0) return 0;
    await this.control.telegramLink.deleteMany({
      where: { id: { in: rows.map((r) => r.id) } },
    });
    for (const r of rows) await this.say(r.chatId, tgText(r.locale).unlinked);
    return rows.length;
  }

  async unlinkChat(chatId: string): Promise<boolean> {
    const r = await this.control.telegramLink.deleteMany({ where: { chatId } });
    return r.count > 0;
  }

  findLink(chatId: string) {
    return this.control.telegramLink.findUnique({ where: { chatId } });
  }

  /** Plain text to a chat. Never throws. */
  async say(chatId: string, text: string): Promise<void> {
    try {
      await this.call('sendMessage', { chat_id: chatId, text });
    } catch (error) {
      this.logger.warn(
        error instanceof Error ? error.message : 'telegram send failed',
      );
    }
  }

  // --- approvals ---------------------------------------------------------------------------

  /** Sends the approval to every linked chat of this workspace's approvers. Never throws. */
  async notifyApproval(
    client: Pick<TenantPrismaClient, 'roleBinding'>,
    tenantId: string,
    input: ApprovalMessageInput,
    now = new Date(),
  ): Promise<number> {
    if (!this.enabled) return 0;
    try {
      const subjects = await this.approvers.listSubjects(tenantId, client);
      if (subjects.length === 0) return 0;
      const links = await this.control.telegramLink.findMany({
        where: { tenantId, subject: { in: subjects } },
      });
      const minutes = Math.max(
        1,
        Math.round((input.expiresAt.getTime() - now.getTime()) / 60_000),
      );
      let sent = 0;
      await Promise.all(
        links.map(async (l) => {
          if (!this.outbound.allow(l.chatId)) return;
          const t = tgText(l.locale);
          const text = [
            t.waiting(input.toolName.slice(0, 40)),
            input.actionId.slice(0, 80),
            t.matchCode(input.matchCode),
            input.highRisk ? t.highRisk : t.answerIn(minutes),
          ].join('\n');
          const reply_markup = input.highRisk
            ? undefined
            : {
                inline_keyboard: [
                  [
                    {
                      text: t.approve,
                      callback_data: signTelegramCallback(
                        this.signingSecret,
                        input.approvalId,
                        'y',
                        l,
                      ),
                    },
                    {
                      text: t.deny,
                      callback_data: signTelegramCallback(
                        this.signingSecret,
                        input.approvalId,
                        'n',
                        l,
                      ),
                    },
                  ],
                ],
              };
          try {
            const msg = await this.call<{ message_id: number }>('sendMessage', {
              chat_id: l.chatId,
              text,
              reply_markup,
            });
            sent += 1;
            await this.control.telegramApprovalMessage.create({
              data: {
                tenantId,
                approvalId: input.approvalId,
                chatId: l.chatId,
                messageId: msg.message_id,
                text,
                // A message without buttons has nothing to disable.
                closedAt: reply_markup ? null : now,
              },
            });
          } catch (error) {
            this.logger.warn(
              error instanceof Error ? error.message : 'telegram send failed',
            );
          }
        }),
      );
      return sent;
    } catch (error) {
      this.logger.warn(
        `telegram fan-out failed: ${error instanceof Error ? error.message : 'error'}`,
      );
      return 0;
    }
  }

  /** Removes the buttons and adds the outcome. Safe to call twice; never throws. */
  async closeApproval(
    tenantId: string,
    approvalId: string,
    outcome: Outcome,
    now = new Date(),
  ): Promise<void> {
    if (!this.enabled) return;
    try {
      const rows = await this.control.telegramApprovalMessage.findMany({
        where: { tenantId, approvalId, closedAt: null },
      });
      if (rows.length === 0) return;
      const links = await this.control.telegramLink.findMany({
        where: { chatId: { in: rows.map((r) => r.chatId) } },
        select: { chatId: true, locale: true },
      });
      for (const r of rows) {
        const claimed = await this.control.telegramApprovalMessage.updateMany({
          where: { id: r.id, closedAt: null },
          data: { closedAt: now },
        });
        if (claimed.count === 0) continue;
        const locale = links.find((l) => l.chatId === r.chatId)?.locale;
        try {
          await this.call('editMessageText', {
            chat_id: r.chatId,
            message_id: r.messageId,
            text: `${r.text}\n\n${tgText(locale).outcome[outcome]}`,
            reply_markup: { inline_keyboard: [] },
          });
        } catch (error) {
          this.logger.warn(
            error instanceof Error ? error.message : 'telegram edit failed',
          );
        }
      }
    } catch (error) {
      this.logger.warn(
        `closing telegram messages failed: ${error instanceof Error ? error.message : 'error'}`,
      );
    }
  }

  /** Disables the buttons of approvals that ended without a message from us (timeout, other channel). */
  async sweep(now = new Date()): Promise<void> {
    if (!this.enabled) return;
    const open = await this.control.telegramApprovalMessage.findMany({
      where: { closedAt: null },
      select: { tenantId: true, approvalId: true },
      distinct: ['approvalId'],
      take: 200,
    });
    const byTenant = new Map<string, string[]>();
    for (const o of open)
      byTenant.set(o.tenantId, [
        ...(byTenant.get(o.tenantId) ?? []),
        o.approvalId,
      ]);
    for (const [tenantId, ids] of byTenant) {
      try {
        const client = await this.tenants.getClient(tenantId);
        const rows = await client.hostApproval.findMany({
          where: { id: { in: ids } },
          select: { id: true, status: true, decision: true, expiresAt: true },
        });
        for (const id of ids) {
          const r = rows.find((x) => x.id === id);
          if (r && r.status === 'PENDING' && r.expiresAt > now) continue;
          const outcome: Outcome =
            r?.status === 'DENIED'
              ? 'deny'
              : r?.status === 'APPROVED'
                ? r.decision === 'approve_8h'
                  ? 'approve_8h'
                  : 'approve_once'
                : 'expired';
          await this.closeApproval(tenantId, id, outcome, now);
        }
      } catch (error) {
        this.logger.warn(
          `sweep skipped one workspace: ${error instanceof Error ? error.message : 'error'}`,
        );
      }
    }
  }

  startSweeper(everyMs = 15_000): void {
    if (!this.enabled || this.timer) return;
    this.timer = setInterval(
      () => void this.sweep().catch(() => undefined),
      everyMs,
    );
    this.timer.unref();
  }

  stopSweeper(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }
}
