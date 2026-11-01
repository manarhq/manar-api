export const DEFAULT_TZ = 'Asia/Dubai';
/** Monday, from 08:00 to 11:59 local: the first run in the window sends; later runs retry a failed send. */
export const SEND_FROM_HOUR = 8;
export const SEND_UNTIL_HOUR = 12;

/** A zone Intl accepts, or the default. */
export function validZone(tz: string | null | undefined): string {
  if (!tz) return DEFAULT_TZ;
  try {
    return new Intl.DateTimeFormat('en', { timeZone: tz }).resolvedOptions()
      .timeZone;
  } catch {
    return DEFAULT_TZ;
  }
}

/** Weekday (1 = Monday ... 7 = Sunday), hour and ISO week label of `now` in `tz`. */
export function localParts(
  now: Date,
  tz: string,
): { weekday: number; hour: number; week: string } {
  const f = new Intl.DateTimeFormat('en-GB', {
    timeZone: validZone(tz),
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    hourCycle: 'h23',
    weekday: 'short',
  });
  const p = Object.fromEntries(
    f.formatToParts(now).map((x) => [x.type, x.value]),
  );
  const weekday =
    ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(p.weekday!) + 1;
  // ISO week of the local calendar date.
  const d = new Date(
    Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day)),
  );
  d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
  const y = d.getUTCFullYear();
  const wk = Math.ceil(
    ((d.getTime() - Date.UTC(y, 0, 1)) / 86_400_000 + 1) / 7,
  );
  return {
    weekday,
    hour: Number(p.hour),
    week: `${y}-W${String(wk).padStart(2, '0')}`,
  };
}

/** True when it is Monday morning (08:00-11:59) in `tz`; also returns the week label. */
export function dueNow(
  now: Date,
  tz: string | null | undefined,
): { due: boolean; week: string } {
  const l = localParts(now, validZone(tz));
  return {
    due:
      l.weekday === 1 && l.hour >= SEND_FROM_HOUR && l.hour < SEND_UNTIL_HOUR,
    week: l.week,
  };
}

export interface DigestTotals {
  actions: number;
  askedYou: number;
  blocked: number;
  secretsKeptSafe: number;
}

const COPY = {
  en: {
    subject: 'Your AI week with Manar',
    title: 'Your AI week',
    lines: (t: DigestTotals) => [
      `${t.actions.toLocaleString('en')} AI actions were checked`,
      `${t.askedYou.toLocaleString('en')} times Manar asked you`,
      `${t.blocked.toLocaleString('en')} actions were blocked`,
      `${t.secretsKeptSafe.toLocaleString('en')} secrets kept safe`,
    ],
    open: 'Open your console',
    foot: 'You get this email every Monday because you use Manar.',
    unsub: 'Stop these emails',
  },
  ar: {
    subject: 'أسبوعك مع الذكاء الاصطناعي في منار',
    title: 'أسبوعك مع الذكاء الاصطناعي',
    lines: (t: DigestTotals) => [
      `تم فحص ${t.actions.toLocaleString('ar-EG')} إجراء للذكاء الاصطناعي`,
      `سألك منار ${t.askedYou.toLocaleString('ar-EG')} مرة`,
      `تم حظر ${t.blocked.toLocaleString('ar-EG')} إجراء`,
      `تم حفظ ${t.secretsKeptSafe.toLocaleString('ar-EG')} من الأسرار`,
    ],
    open: 'افتح لوحة التحكم',
    foot: 'تصلك هذه الرسالة كل يوم اثنين لأنك تستخدم منار.',
    unsub: 'إيقاف هذه الرسائل',
  },
} as const;

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** Subject, HTML and plain text of the weekly email. Totals only; no names of files, devices or prompts. */
export function renderDigest(args: {
  locale: 'en' | 'ar';
  totals: DigestTotals;
  consoleUrl: string;
  unsubscribeUrl: string;
}) {
  const c = COPY[args.locale];
  const dir = args.locale === 'ar' ? 'rtl' : 'ltr';
  const lines = c.lines(args.totals);
  // Email clients ignore CSS variables, so the Midnight colours are inline here.
  const html = `<!doctype html><html lang="${args.locale}" dir="${dir}"><body style="margin:0;background:#02070A;font-family:'Readex Pro',Arial,sans-serif;color:#fff">
<div style="max-width:520px;margin:0 auto;padding:32px 24px">
<h1 style="font-size:22px;margin:0 0 20px">${esc(c.title)}</h1>
<ul style="padding-${dir === 'rtl' ? 'right' : 'left'}:20px;line-height:1.9;font-size:16px">${lines.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
<p><a href="${esc(args.consoleUrl)}" style="display:inline-block;background:#0297DE;color:#02070A;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600">${esc(c.open)}</a></p>
<p style="font-size:12px;color:#9aa7b0;margin-top:32px">${esc(c.foot)} <a href="${esc(args.unsubscribeUrl)}" style="color:#9aa7b0">${esc(c.unsub)}</a></p>
</div></body></html>`;
  const text = `${c.title}\n\n${lines.map((l) => `- ${l}`).join('\n')}\n\n${c.open}: ${args.consoleUrl}\n\n${c.foot}\n${c.unsub}: ${args.unsubscribeUrl}\n`;
  return { subject: c.subject, html, text };
}
