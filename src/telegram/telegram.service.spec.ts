/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-call -- hand-written fakes for the control DB, the tenant DB and the Bot API */
import { describe, expect, it, vi } from 'vitest';
import { TelegramBotHandler } from './telegram-bot.handler';
import { TelegramService } from './telegram.service';
import {
  signTelegramCallback,
  verifyTelegramCallback,
} from '../phone/phone-token';

const B1 = { chatId: '111', tenantId: 't1', subject: 'u1' };
const SECRET = 'unit-test-signing-secret-0123456789';
const WEBHOOK = 'w'.repeat(40);
const ID = '3f2b1c9e-8d7a-4b6c-9e5d-1a2b3c4d5e6f';

function world() {
  const calls: { method: string; body: Record<string, any> }[] = [];
  const fetchFake = vi.fn((url: string, init: RequestInit) => {
    const method = url.split('/').pop()!;
    calls.push({ method, body: JSON.parse(init.body as string) });
    return Promise.resolve(
      new Response(
        JSON.stringify({ ok: true, result: { message_id: calls.length } }),
      ),
    );
  });
  const links: any[] = [];
  const codes = new Map<string, any>();
  const msgs: any[] = [];
  const control: any = {
    tenant: { findUnique: () => Promise.resolve({ name: 'Acme Security' }) },
    telegramLink: {
      findMany: ({ where }: any) =>
        Promise.resolve(
          links.filter(
            (l) =>
              (!where.tenantId || l.tenantId === where.tenantId) &&
              (!where.subject?.in || where.subject.in.includes(l.subject)) &&
              (!where.subject || typeof where.subject === 'string'
                ? l.subject === where.subject || !where.subject
                : true) &&
              (!where.chatId?.in || where.chatId.in.includes(l.chatId)),
          ),
        ),
      findUnique: ({ where }: any) =>
        Promise.resolve(links.find((l) => l.chatId === where.chatId) ?? null),
      upsert: ({ where, create, update }: any) => {
        const i = links.findIndex((l) => l.chatId === where.chatId);
        if (i >= 0) links[i] = { ...links[i], ...update };
        else
          links.push({
            id: `l${links.length}`,
            createdAt: new Date(),
            ...create,
          });
        return Promise.resolve({});
      },
      deleteMany: ({ where }: any) => {
        const before = links.length;
        for (let i = links.length - 1; i >= 0; i--)
          if (
            links[i].chatId === where.chatId ||
            where.id?.in?.includes(links[i].id)
          )
            links.splice(i, 1);
        return Promise.resolve({ count: before - links.length });
      },
    },
    telegramLinkCode: {
      deleteMany: ({ where }: any) => {
        if (where.codeHash)
          return Promise.resolve({
            count: codes.delete(where.codeHash) ? 1 : 0,
          });
        for (const [k, v] of codes)
          if (v.subject === where.subject) codes.delete(k);
        return Promise.resolve({ count: 0 });
      },
      create: ({ data }: any) => (
        codes.set(data.codeHash, data),
        Promise.resolve(data)
      ),
      findUnique: ({ where }: any) =>
        Promise.resolve(codes.get(where.codeHash) ?? null),
    },
    telegramApprovalMessage: {
      create: ({ data }: any) => (
        msgs.push({ id: `m${msgs.length}`, closedAt: null, ...data }),
        Promise.resolve({})
      ),
      findMany: ({ where }: any) =>
        Promise.resolve(
          msgs.filter(
            (m) =>
              m.closedAt === null &&
              (!where.approvalId || m.approvalId === where.approvalId),
          ),
        ),
      updateMany: ({ where, data }: any) => {
        const m = msgs.find((x) => x.id === where.id && x.closedAt === null);
        if (m) m.closedAt = data.closedAt;
        return Promise.resolve({ count: m ? 1 : 0 });
      },
    },
    $transaction: (ops: Promise<unknown>[]) => Promise.all(ops),
  };
  const approval: any = {
    id: ID,
    status: 'PENDING',
    highRisk: false,
    expiresAt: new Date(Date.now() + 120_000),
    decision: null,
  };
  const tenantClient: any = {
    hostApproval: { findMany: () => Promise.resolve([approval]) },
  };
  const tenants: any = { getClient: () => Promise.resolve(tenantClient) };
  let approver = true;
  const approvers: any = {
    listSubjects: () => Promise.resolve(['u1']),
    canApprove: () => Promise.resolve(approver),
  };
  const config: any = {
    get: (k: string) =>
      ({
        TELEGRAM_BOT_TOKEN: '123:abc',
        TELEGRAM_WEBHOOK_SECRET: WEBHOOK,
        TELEGRAM_BOT_USERNAME: 'manar_test_bot',
        APPROVAL_GRANT_SIGNING_SECRET: SECRET,
      })[k],
  };
  const tg = new TelegramService(
    control,
    tenants,
    approvers,
    config,
    fetchFake,
  );
  const decide = vi.fn((_c: any, _t: string, input: any) => {
    approval.status = input.decision === 'deny' ? 'DENIED' : 'APPROVED';
    approval.decision = input.decision;
    void tg.closeApproval('t1', ID, input.decision);
    return Promise.resolve({
      id: ID,
      status: approval.status,
      decision: input.decision,
    });
  });
  const approvals: any = { get: () => Promise.resolve(approval), decide };
  const audit: any = { recordSafely: vi.fn().mockResolvedValue(undefined) };
  let restricted = false;
  const restrictions: any = {
    activeForSubject: () => Promise.resolve(restricted),
  };
  const bot = new TelegramBotHandler(
    tg,
    tenants,
    approvers,
    approvals,
    audit,
    restrictions,
  );
  const private_ = (id: number) => ({ id, type: 'private' });
  return {
    tg,
    bot,
    calls,
    links,
    codes,
    msgs,
    approval,
    decide,
    audit,
    setApprover: (v: boolean) => (approver = v),
    setRestricted: (v: boolean) => (restricted = v),
    start: (chat: number, text: string) =>
      bot.handle({
        message: { chat: private_(chat), text, from: { language_code: 'en' } },
      }),
    press: (chat: number, data: string) =>
      bot.handle({
        callback_query: { id: 'cb', data, message: { chat: private_(chat) } },
      }),
  };
}

const sent = (w: ReturnType<typeof world>, m: string) =>
  w.calls.filter((c) => c.method === m);
const button = (w: ReturnType<typeof world>, i: number) =>
  sent(w, 'sendMessage').at(-1)!.body.reply_markup.inline_keyboard[0][i]
    .callback_data as string;

describe('webhook secret', () => {
  it('accepts only the exact secret', () => {
    const w = world();
    expect(w.tg.verifyWebhookSecret(WEBHOOK)).toBe(true);
    for (const bad of [undefined, '', 'x', WEBHOOK + 'a', WEBHOOK.slice(1)])
      expect(w.tg.verifyWebhookSecret(bad)).toBe(false);
  });
});

describe('link flow', () => {
  it('a code from the console links one private chat, once', async () => {
    const w = world();
    const { code } = await w.tg.createLinkCode('t1', 'u1');
    await w.start(111, `/start ${code.replace('-', '')}`);
    expect(w.links).toHaveLength(1);
    expect(w.links[0]).toMatchObject({
      tenantId: 't1',
      subject: 'u1',
      chatId: '111',
    });
    // Reuse of the same code from another chat fails.
    await w.start(222, `/start ${code}`);
    expect(w.links).toHaveLength(1);
    expect(sent(w, 'sendMessage').at(-1)!.body.text).toMatch(/not valid/);
    expect(w.audit.recordSafely).toHaveBeenCalledTimes(1);
  });

  it('refuses groups, wrong codes (and throttles guessing), and a person who stopped being an approver', async () => {
    const w = world();
    await w.bot.handle({
      message: { chat: { id: 5, type: 'group' }, text: '/start AAAAAAAA' },
    });
    expect(w.calls).toHaveLength(0);
    for (let i = 0; i < 6; i++) await w.start(333, '/start WRONGCODE');
    expect(sent(w, 'sendMessage').at(-1)!.body.text).toMatch(/Too many/);
    const w2 = world();
    const { code } = await w2.tg.createLinkCode('t1', 'u1');
    w2.setApprover(false);
    await w2.start(444, `/start ${code}`);
    expect(w2.links).toHaveLength(0);
  });

  it('names the workspace on success', async () => {
    const w = world();
    const { code } = await w.tg.createLinkCode('t1', 'u1');
    await w.start(111, `/start ${code}`);
    expect(sent(w, 'sendMessage').at(-1)!.body.text).toMatch(/Acme Security/);
  });

  it('refuses a chat that belongs to another person, and keeps the old link', async () => {
    const w = world();
    const a = await w.tg.createLinkCode('t1', 'u1');
    await w.start(111, `/start ${a.code}`);
    const b = await w.tg.createLinkCode('t1', 'u2');
    await w.start(111, `/start ${b.code}`);
    expect(w.links).toHaveLength(1);
    expect(w.links[0]).toMatchObject({ subject: 'u1' });
    expect(sent(w, 'sendMessage').at(-1)!.body.text).toMatch(
      /linked to another account/,
    );
  });

  it('tells the person s other chats when a new chat is linked', async () => {
    const w = world();
    const a = await w.tg.createLinkCode('t1', 'u1');
    await w.start(111, `/start ${a.code}`);
    const b = await w.tg.createLinkCode('t1', 'u1');
    await w.start(222, `/start ${b.code}`);
    const toOld = sent(w, 'sendMessage').filter(
      (c) => c.body.chat_id === '111',
    );
    expect(toOld.at(-1)!.body.text).toMatch(
      /Another Telegram chat was just linked/,
    );
  });

  it('/stop unlinks', async () => {
    const w = world();
    const { code } = await w.tg.createLinkCode('t1', 'u1');
    await w.start(111, `/start ${code}`);
    await w.start(111, '/stop');
    expect(w.links).toHaveLength(0);
  });
});

describe('approvals over Telegram', () => {
  async function linked() {
    const w = world();
    const { code } = await w.tg.createLinkCode('t1', 'u1');
    await w.start(111, `/start ${code}`);
    w.calls.length = 0;
    await w.tg.notifyApproval({} as never, 't1', {
      approvalId: ID,
      toolName: 'Cursor',
      actionId: 'file.write',
      matchCode: '3F2B',
      highRisk: false,
      expiresAt: new Date(Date.now() + 120_000),
    });
    return w;
  }

  it('sends two signed buttons that approve or deny once, and the click closes the message', async () => {
    const w = await linked();
    const a = button(w, 0);
    expect(verifyTelegramCallback(SECRET, a, B1)).toEqual({
      approvalId: ID,
      choice: 'y',
    });
    await w.press(111, a);
    expect(w.decide).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({
        via: 'telegram',
        decision: 'approve_once',
        subject: 'u1',
      }),
    );
    await new Promise((r) => setTimeout(r, 10));
    const edit = sent(w, 'editMessageText')[0]!.body;
    expect(edit.reply_markup).toEqual({ inline_keyboard: [] });
    expect(edit.text).toMatch(/Approved once/);
  });

  it('the message shows the tool, action type, match code and the approval own time, never the resource', async () => {
    const w = await linked();
    const text = sent(w, 'sendMessage')[0]!.body.text as string;
    expect(text).toMatch(/Cursor/);
    expect(text).toMatch(/file\.write/);
    expect(text).toMatch(/3F2B/);
    expect(text).toMatch(/within 2 min/);
    expect(text).not.toMatch(/credentials|\/u\//);
    const w2 = world();
    const { code } = await w2.tg.createLinkCode('t1', 'u1');
    await w2.start(111, `/start ${code}`);
    w2.calls.length = 0;
    await w2.tg.notifyApproval({} as never, 't1', {
      approvalId: ID,
      toolName: 'Cursor',
      actionId: 'file.write',
      matchCode: '3F2B',
      highRisk: false,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    expect(sent(w2, 'sendMessage')[0]!.body.text).toMatch(/within 5 min/);
  });

  it('buttons are void after the chat is linked to another person', async () => {
    const w = await linked();
    const a = button(w, 0);
    w.links[0].subject = 'u9';
    await w.press(111, a);
    expect(w.decide).not.toHaveBeenCalled();
  });

  it('a button pressed in another chat, or a forged one, does nothing', async () => {
    const w = await linked();
    const a = button(w, 1);
    await w.press(999, a);
    await w.press(111, a.replace('.n.', '.y.'));
    expect(w.decide).not.toHaveBeenCalled();
  });

  it('high-risk approvals get a message with no buttons, and the callback is refused anyway', async () => {
    const w = world();
    const { code } = await w.tg.createLinkCode('t1', 'u1');
    await w.start(111, `/start ${code}`);
    w.calls.length = 0;
    await w.tg.notifyApproval({} as never, 't1', {
      approvalId: ID,
      toolName: 'Cursor',
      actionId: 'file.write',
      matchCode: '3F2B',
      highRisk: true,
      expiresAt: new Date(Date.now() + 120_000),
    });
    expect(sent(w, 'sendMessage')[0]!.body.reply_markup).toBeUndefined();
    w.approval.highRisk = true;
    await w.press(111, signTelegramCallback(SECRET, ID, 'y', B1));
    expect(w.decide).not.toHaveBeenCalled();
  });

  it('an approval that times out has its buttons removed by the sweep', async () => {
    const w = await linked();
    await w.tg.sweep();
    expect(sent(w, 'editMessageText')).toHaveLength(0);
    w.approval.expiresAt = new Date(Date.now() - 1000);
    await w.tg.sweep();
    const edit = sent(w, 'editMessageText')[0]!.body;
    expect(edit.reply_markup).toEqual({ inline_keyboard: [] });
    expect(edit.text).toMatch(/No answer in time/);
    await w.tg.sweep();
    expect(sent(w, 'editMessageText')).toHaveLength(1);
  });

  it('a press after the approval timed out is told so and decides nothing', async () => {
    const w = await linked();
    w.decide.mockRejectedValueOnce(new Error('already decided or expired'));
    await w.press(111, button(w, 0));
    expect(sent(w, 'answerCallbackQuery').at(-1)!.body.text).toMatch(
      /Already decided/,
    );
  });

  it('a person Manar suspended or banned cannot decide from Telegram (DESK spec §9.2)', async () => {
    const w = await linked();
    w.setRestricted(true);
    await w.press(111, button(w, 0));
    expect(w.decide).not.toHaveBeenCalled();
  });

  it('a person who is no longer an approver cannot decide', async () => {
    const w = await linked();
    w.setApprover(false);
    await w.press(111, button(w, 0));
    expect(w.decide).not.toHaveBeenCalled();
  });
});
