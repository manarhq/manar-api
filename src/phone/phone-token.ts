import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Signed one-shot tokens for deciding an approval from a phone. Keys are derived from the
 * approval signing secret with a label per purpose, so a token for one channel is never valid on
 * the other.
 */
const key = (secret: string, label: string) =>
  createHmac('sha256', secret).update(label).digest();

const b64 = (b: Buffer) => b.toString('base64url');

function same(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export interface PushActionClaims {
  /** Approval id. */
  a: string;
  /** Keycloak subject the push was sent to. */
  s: string;
  /** Tenant id. */
  t: string;
  /** Expiry, ms since epoch (the approval's own expiry). */
  e: number;
  /** Single-use nonce. */
  n: string;
}

export function signPushAction(
  secret: string,
  claims: Omit<PushActionClaims, 'n'>,
): { token: string; nonce: string } {
  const nonce = b64(randomBytes(16));
  const body = b64(Buffer.from(JSON.stringify({ ...claims, n: nonce })));
  const sig = b64(
    createHmac('sha256', key(secret, 'phone.push.v1')).update(body).digest(),
  );
  return { token: `${body}.${sig}`, nonce };
}

/** Null for anything that is not a well-formed, correctly signed, unexpired token. */
export function verifyPushAction(
  secret: string,
  token: string,
  now: number = Date.now(),
): PushActionClaims | null {
  const [body, sig, extra] = token.split('.');
  if (!body || !sig || extra !== undefined) return null;
  const want = b64(
    createHmac('sha256', key(secret, 'phone.push.v1')).update(body).digest(),
  );
  if (!same(sig, want)) return null;
  try {
    const c = JSON.parse(
      Buffer.from(body, 'base64url').toString(),
    ) as PushActionClaims;
    if (
      typeof c.a !== 'string' ||
      typeof c.s !== 'string' ||
      typeof c.t !== 'string' ||
      typeof c.n !== 'string' ||
      typeof c.e !== 'number' ||
      c.e <= now
    )
      return null;
    return c;
  } catch {
    return null;
  }
}

/** Short code both the device prompt and the phone show, so a person can tell requests apart. */
export function approvalMatchCode(approvalId: string): string {
  return approvalId.replace(/-/g, '').slice(0, 4).toUpperCase();
}

/** Keyed hash of a link code: a leaked table of hashes cannot be brute-forced without the server secret. */
export function linkCodeHash(secret: string, code: string): string {
  return createHmac('sha256', key(secret, 'phone.telegram.code.v1'))
    .update(code.toUpperCase().replace(/[^A-Z0-9]/g, ''))
    .digest('hex');
}

export type TelegramChoice = 'y' | 'n';

export interface TelegramBinding {
  chatId: string;
  tenantId: string;
  subject: string;
}

// The workspace and person are signed but not carried in callback_data (64-byte limit): the
// verifier supplies them from the link row, so a chat re-linked to someone else voids old buttons.
const tgSig = (
  secret: string,
  approvalId: string,
  choice: string,
  b: TelegramBinding,
) =>
  b64(
    createHmac('sha256', key(secret, 'phone.telegram.v1'))
      .update(
        JSON.stringify([approvalId, choice, b.chatId, b.tenantId, b.subject]),
      )
      .digest()
      .subarray(0, 16),
  );

/** `a.<approval id>.<y|n>.<sig>`: at most 63 bytes for a 36-character id (Telegram allows 64). */
export function signTelegramCallback(
  secret: string,
  approvalId: string,
  choice: TelegramChoice,
  binding: TelegramBinding,
): string {
  return `a.${approvalId}.${choice}.${tgSig(secret, approvalId, choice, binding)}`;
}

/** The signature binds the approval, the choice, the chat, the workspace and the person. */
export function verifyTelegramCallback(
  secret: string,
  data: string,
  binding: TelegramBinding,
): { approvalId: string; choice: TelegramChoice } | null {
  const m = /^a\.([0-9a-f-]{36})\.([yn])\.([A-Za-z0-9_-]{22})$/.exec(data);
  if (!m) return null;
  const [, approvalId, choice, sig] = m as unknown as [
    string,
    string,
    TelegramChoice,
    string,
  ];
  return same(sig, tgSig(secret, approvalId, choice, binding))
    ? { approvalId, choice }
    : null;
}
