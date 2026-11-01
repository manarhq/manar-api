const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const COPY = {
  en: {
    subject: 'Your free Pro months end soon',
    title: 'Keep Pro after your free months',
    body: (date: string) =>
      `Your free Pro months end on ${date}. Add a card and your billing details to keep Pro. UAE VAT is added when you pay. If you do nothing, nothing is charged and your workspace goes back to the Free plan.`,
    cta: 'Keep Pro',
  },
  ar: {
    subject: 'أشهر Pro المجانية لديك على وشك الانتهاء',
    title: 'احتفظ بخطة Pro بعد الأشهر المجانية',
    body: (date: string) =>
      `تنتهي أشهر Pro المجانية في ${date}. أضف بطاقة وبيانات الفوترة للاحتفاظ بخطة Pro. تُضاف ضريبة القيمة المضافة في الإمارات عند الدفع. إذا لم تفعل شيئاً فلن يُحصَّل أي مبلغ وتعود مساحة عملك إلى الخطة المجانية.`,
    cta: 'احتفظ بخطة Pro',
  },
} as const;

/** The reminder sent 7 days before the launch-offer trial ends. `link` opens the billing page. */
export function renderTrialReminder(args: {
  locale: 'en' | 'ar';
  endsAt: Date;
  link: string;
}) {
  const c = COPY[args.locale];
  const date = new Intl.DateTimeFormat(
    args.locale === 'ar' ? 'ar-AE' : 'en-GB',
    {
      dateStyle: 'long',
      timeZone: 'Asia/Dubai',
    },
  ).format(args.endsAt);
  const dir = args.locale === 'ar' ? 'rtl' : 'ltr';
  const html = `<!doctype html><html lang="${args.locale}" dir="${dir}"><body style="margin:0;background:#02070A;font-family:'Readex Pro',Arial,sans-serif;color:#fff"><div style="max-width:520px;margin:0 auto;padding:32px 24px"><h1 style="font-size:22px;margin:0 0 16px">${esc(c.title)}</h1><p style="line-height:1.8;font-size:16px">${esc(c.body(date))}</p><p><a href="${esc(args.link)}" style="display:inline-block;background:#0297DE;color:#02070A;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600">${esc(c.cta)}</a></p></div></body></html>`;
  return {
    subject: c.subject,
    html,
    text: `${c.title}\n\n${c.body(date)}\n\n${c.cta}: ${args.link}\n`,
  };
}
