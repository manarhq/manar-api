export type TelegramLocale = 'en' | 'ar';

export type Outcome =
  'approve_once' | 'approve_8h' | 'approve_always' | 'deny' | 'expired';

interface Strings {
  approve: string;
  deny: string;
  waiting: (tool: string) => string;
  answerIn: (minutes: number) => string;
  highRisk: string;
  outcome: Record<Outcome, string>;
  matchCode: (code: string) => string;
  linked: (workspace: string) => string;
  linkedElsewhere: string;
  relinked: (workspace: string) => string;
  badCode: string;
  unlinked: string;
  help: string;
  notLinked: string;
  openConsole: string;
  gone: string;
  tooMany: string;
  notApprover: string;
}

const en: Strings = {
  approve: 'Approve once',
  deny: 'Deny',
  waiting: (tool) => `WARDEN: ${tool} is waiting for your decision.`,
  answerIn: (m) => `Answer within ${m} min or it is denied.`,
  highRisk: 'This one is high risk. Open the console to decide.',
  outcome: {
    approve_once: 'Approved once.',
    approve_8h: 'Approved for 8 hours.',
    approve_always: 'Always allowed for this site.',
    deny: 'Denied.',
    expired: 'No answer in time. Denied.',
  },
  matchCode: (c) => `Match code ${c}. It is the same on your computer.`,
  linked: (w) =>
    `Linked to ${w}. Approvals for this workspace will arrive here.`,
  linkedElsewhere:
    'This chat is linked to another account. Send /stop first, then link again.',
  relinked: (w) =>
    `Another Telegram chat was just linked to your ${w} account. If that was not you, unlink in the console.`,
  badCode:
    'That code is not valid or has expired. Make a new one in the console under Settings, Notifications.',
  unlinked: 'Unlinked. You will not get approvals here any more.',
  help: 'To link this chat, send /start and the code from the console (Settings, Notifications). Send /stop to unlink.',
  notLinked: 'This chat is not linked to a Manar account.',
  openConsole: 'Open the console to decide this one.',
  gone: 'Already decided, or it ran out of time.',
  tooMany: 'Too many attempts. Try again later.',
  notApprover: 'You can no longer approve in this workspace.',
};

const ar: Strings = {
  approve: 'موافقة لمرة واحدة',
  deny: 'رفض',
  waiting: (tool) => `WARDEN: ${tool} ينتظر قرارك.`,
  answerIn: (m) => `أجب خلال ${m} دقيقة وإلا سيُرفض الطلب.`,
  highRisk: 'هذا الطلب عالي الخطورة. افتح لوحة التحكم لتقرر.',
  outcome: {
    approve_once: 'تمت الموافقة لمرة واحدة.',
    approve_8h: 'تمت الموافقة لمدة 8 ساعات.',
    approve_always: 'مسموح دائماً لهذا الموقع.',
    deny: 'تم الرفض.',
    expired: 'انتهت المهلة دون إجابة. تم الرفض.',
  },
  matchCode: (c) => `رمز المطابقة ${c}. هو نفسه على حاسوبك.`,
  linked: (w) => `تم الربط مع ${w}. ستصل موافقات مساحة العمل هذه إلى هنا.`,
  linkedElsewhere:
    'هذه المحادثة مرتبطة بحساب آخر. أرسل /stop أولا ثم اربط من جديد.',
  relinked: (w) =>
    `تم للتو ربط محادثة تيليغرام أخرى بحسابك في ${w}. إن لم تكن أنت، ألغِ الربط من لوحة التحكم.`,
  badCode:
    'الرمز غير صالح أو انتهت صلاحيته. أنشئ رمزا جديدا في لوحة التحكم من الإعدادات ثم الإشعارات.',
  unlinked: 'تم إلغاء الربط. لن تصلك الموافقات هنا بعد الآن.',
  help: 'لربط هذه المحادثة أرسل /start ثم الرمز من لوحة التحكم (الإعدادات، الإشعارات). أرسل /stop لإلغاء الربط.',
  notLinked: 'هذه المحادثة غير مرتبطة بحساب في منار.',
  openConsole: 'افتح لوحة التحكم لتقرر في هذا الطلب.',
  gone: 'تم البت فيه مسبقا أو انتهت مهلته.',
  tooMany: 'محاولات كثيرة. حاول لاحقا.',
  notApprover: 'لم تعد لديك صلاحية الموافقة في مساحة العمل هذه.',
};

export const tgText = (locale: string | null | undefined): Strings =>
  locale === 'ar' ? ar : en;

export const tgLocale = (languageCode: string | undefined): TelegramLocale =>
  languageCode?.toLowerCase().startsWith('ar') ? 'ar' : 'en';
