export type TelegramLocale = 'en' | 'ar';

export type Outcome = 'approve_once' | 'approve_8h' | 'deny' | 'expired';

interface Strings {
  approve: string;
  deny: string;
  waiting: (tool: string) => string;
  answerIn: (minutes: number) => string;
  highRisk: string;
  outcome: Record<Outcome, string>;
  linked: string;
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
    deny: 'Denied.',
    expired: 'No answer in time. Denied.',
  },
  linked: 'Linked. Approvals for your workspace will arrive here.',
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
    deny: 'تم الرفض.',
    expired: 'انتهت المهلة دون إجابة. تم الرفض.',
  },
  linked: 'تم الربط. ستصل موافقات مساحة عملك إلى هنا.',
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
