/** Billing emails in EN and AR: usage alerts and the personal trial reminders. */
type Locale = 'en' | 'ar';

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const SAFE = {
  en: 'Protection is not affected: blocks, approvals, the vault and the audit record keep working.',
  ar: 'الحماية لا تتأثر: الحظر والموافقات والخزنة وسجل التدقيق تبقى تعمل.',
};

const ALERT = {
  en: {
    ai: (p: number) =>
      `You have used ${p}% of this month's included AI actions`,
    minutes: (p: number) =>
      `You have used ${p}% of this month's included cloud-agent minutes`,
    cap: (p: number) => `You have reached ${p}% of your monthly spend cap`,
    low: () => 'Your Manar credits are running low',
    body100:
      'Paid extras above your allowance now use credits. When credits or the cap run out, AI answers and cloud agents pause until you add credits or raise the cap.',
    body: 'You can see live usage, buy credits, set a cap or turn on auto top-up on the usage page.',
    cta: 'Open usage and billing',
  },
  ar: {
    ai: (p: number) =>
      `استخدمت ${p}% من إجراءات الذكاء الاصطناعي المضمّنة لهذا الشهر`,
    minutes: (p: number) =>
      `استخدمت ${p}% من دقائق الوكلاء السحابيين المضمّنة لهذا الشهر`,
    cap: (p: number) => `بلغت ${p}% من الحد الشهري للإنفاق`,
    low: () => 'رصيدك من أرصدة منار يقترب من النفاد',
    body100:
      'الإضافات المدفوعة فوق الحصة المضمّنة تُخصم الآن من الأرصدة. عند نفاد الأرصدة أو بلوغ الحد، تتوقف إجابات الذكاء الاصطناعي والوكلاء السحابيون مؤقتاً حتى تضيف أرصدة أو ترفع الحد.',
    body: 'يمكنك متابعة الاستخدام مباشرة وشراء أرصدة وتحديد حد وتفعيل الشحن التلقائي من صفحة الاستخدام.',
    cta: 'افتح الاستخدام والفوترة',
  },
} as const;

const TRIAL = {
  en: {
    subject: (left: number) =>
      left > 0
        ? `Your Manar trial ends in ${left} ${left === 1 ? 'day' : 'days'}`
        : 'Your Manar trial ends today',
    value: (n: number) =>
      n > 0
        ? `In your trial, Manar blocked ${n} risky ${n === 1 ? 'action' : 'actions'}.`
        : 'In your trial, Manar watched your AI tools and kept a signed record.',
    body: 'When the trial ends you move to the Free plan: 1 device, safety on, 20 AI actions a month and 30 days of history. Your other devices keep blocking risky actions. Pro is $5 a month with 2 active devices and 300 AI actions.',
    cta: 'See plans',
  },
  ar: {
    subject: (left: number) =>
      left > 0
        ? `تنتهي تجربتك في منار خلال ${left} ${left === 1 ? 'يوم' : 'أيام'}`
        : 'تنتهي تجربتك في منار اليوم',
    value: (n: number) =>
      n > 0
        ? `خلال تجربتك، حظر منار ${n} من الإجراءات الخطرة.`
        : 'خلال تجربتك، راقب منار أدوات الذكاء الاصطناعي لديك واحتفظ بسجل موقّع.',
    body: 'عند انتهاء التجربة تنتقل إلى الخطة المجانية: جهاز واحد، الحماية مفعّلة، 20 إجراء ذكاء اصطناعي شهرياً وسجل لمدة 30 يوماً. أجهزتك الأخرى تواصل حظر الإجراءات الخطرة. خطة Pro بسعر 5 دولارات شهرياً وتشمل جهازين نشطين و300 إجراء ذكاء اصطناعي.',
    cta: 'اطّلع على الخطط',
  },
} as const;

function page(
  locale: Locale,
  title: string,
  paras: string[],
  cta: string,
  link: string,
) {
  const dir = locale === 'ar' ? 'rtl' : 'ltr';
  const body = paras
    .map((p) => `<p style="line-height:1.8;font-size:16px">${esc(p)}</p>`)
    .join('');
  return `<!doctype html><html lang="${locale}" dir="${dir}"><body style="margin:0;background:#02070A;font-family:'Readex Pro',Arial,sans-serif;color:#fff"><div style="max-width:520px;margin:0 auto;padding:32px 24px"><h1 style="font-size:22px;margin:0 0 16px">${esc(title)}</h1>${body}<p><a href="${esc(link)}" style="display:inline-block;background:#0297DE;color:#02070A;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600">${esc(cta)}</a></p></div></body></html>`;
}

/** One usage alert. `key` is `ai:80`, `minutes:100`, `cap:50` or `credits:low`. */
export function renderUsageAlert(args: {
  locale: Locale;
  key: string;
  link: string;
}) {
  const c = ALERT[args.locale];
  const [name, raw] = args.key.split(':') as [string, string];
  const p = Number(raw);
  const title =
    name === 'ai'
      ? c.ai(p)
      : name === 'minutes'
        ? c.minutes(p)
        : name === 'cap'
          ? c.cap(p)
          : c.low();
  const paras = [
    ...(p === 100 || name === 'credits' ? [c.body100] : []),
    c.body,
    SAFE[args.locale],
  ];
  return {
    subject: title,
    html: page(args.locale, title, paras, c.cta, args.link),
    text: `${title}\n\n${paras.join('\n\n')}\n\n${c.cta}: ${args.link}\n`,
  };
}

/** The personal trial reminder for day 10, 13 or 14. */
export function renderTrialReminder(args: {
  locale: Locale;
  daysLeft: number;
  blocked: number;
  link: string;
}) {
  const c = TRIAL[args.locale];
  const title = c.subject(args.daysLeft);
  const paras = [c.value(args.blocked), c.body];
  return {
    subject: title,
    html: page(args.locale, title, paras, c.cta, args.link),
    text: `${title}\n\n${paras.join('\n\n')}\n\n${c.cta}: ${args.link}\n`,
  };
}
