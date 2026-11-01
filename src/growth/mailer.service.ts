import { createHash, createHmac } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { isPlaceholderEmail } from '../contact/contact-email.service';
import type { AppConfig } from '../config/env.validation';
import { growthSetting } from './growth.config';

export interface Mail {
  to: string;
  subject: string;
  html: string;
  text: string;
  /** Extra headers, e.g. List-Unsubscribe. */
  headers?: Record<string, string>;
}

/** Parses `endpoint=https://x.communication.azure.com/;accesskey=BASE64`. */
export function parseAcs(
  conn: string,
): { endpoint: string; key: Buffer } | null {
  const parts = new Map(
    conn
      .split(';')
      .map((p) => p.trim())
      .filter(Boolean)
      .map((p) => [
        p.slice(0, p.indexOf('=')).toLowerCase(),
        p.slice(p.indexOf('=') + 1),
      ]),
  );
  const endpoint = parts.get('endpoint');
  const key = parts.get('accesskey');
  if (!endpoint || !key || !endpoint.startsWith('https://')) return null;
  return {
    endpoint: endpoint.replace(/\/+$/, ''),
    key: Buffer.from(key, 'base64'),
  };
}

/** HMAC headers Azure Communication Services expects (docs: "Sign an HTTP request"). */
export function acsHeaders(
  key: Buffer,
  host: string,
  pathAndQuery: string,
  body: string,
  now = new Date(),
): Record<string, string> {
  const date = now.toUTCString();
  const hash = createHash('sha256').update(body).digest('base64');
  const signature = createHmac('sha256', key)
    .update(`POST\n${pathAndQuery}\n${date};${host};${hash}`)
    .digest('base64');
  return {
    'x-ms-date': date,
    'x-ms-content-sha256': hash,
    Authorization: `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`,
  };
}

/**
 * Sends through Azure Communication Services Email (REST, no SDK). `send` returns false when mail
 * is not configured or the call failed; it never throws and never logs the address or the body.
 */
@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);

  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  get configured(): boolean {
    return !!this.acs();
  }

  async send(mail: Mail): Promise<boolean> {
    const acs = this.acs();
    if (!acs) return false;
    // The shared realm's placeholder addresses are never real mailboxes.
    if (isPlaceholderEmail(mail.to)) return false;
    const path = '/emails:send?api-version=2023-03-31';
    const body = JSON.stringify({
      senderAddress: growthSetting(this.config, 'MAIL_FROM'),
      replyTo: [{ address: growthSetting(this.config, 'MAIL_REPLY_TO') }],
      recipients: { to: [{ address: mail.to }] },
      content: { subject: mail.subject, plainText: mail.text, html: mail.html },
      headers: mail.headers,
      userEngagementTrackingDisabled: true,
    });
    try {
      const res = await fetch(`${acs.endpoint}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...acsHeaders(acs.key, new URL(acs.endpoint).host, path, body),
        },
        body,
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) {
        this.logger.warn(`ACS email refused: HTTP ${res.status}`);
        return false;
      }
      return true;
    } catch (error) {
      this.logger.warn(
        `ACS email failed: ${error instanceof Error ? error.name : 'error'}`,
      );
      return false;
    }
  }

  private acs() {
    const c = this.config.get('ACS_EMAIL_CONNECTION_STRING', { infer: true });
    return c ? parseAcs(c) : null;
  }
}
