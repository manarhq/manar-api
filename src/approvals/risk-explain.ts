/**
 * Plain-words risk explanation for a WARDEN prompt and the console approvals page (launch spec 4.6,
 * founder decision 1 Nov). Deterministic templates per action type: no model, and the resource is
 * never copied into the text (it is shown next to it), so a hostile file name or command cannot
 * write the explanation. Both languages come from here so the device and the console say the same.
 */
export interface RiskExplanation {
  en: string;
  ar: string;
}

type Pair = RiskExplanation;

const READ: Pair = {
  en: 'It wants to read a file. What it reads can be sent to the AI company.',
  ar: 'يريد قراءة ملف. ما يقرؤه قد يُرسل إلى شركة الذكاء الاصطناعي.',
};
const CHANGE: Pair = {
  en: 'It wants to change a file. The old contents may be overwritten.',
  ar: 'يريد تعديل ملف. قد يُستبدل المحتوى القديم.',
};
const DELETE: Pair = {
  en: 'It wants to delete something. Deleted files may not come back.',
  ar: 'يريد حذف شيء. قد لا يمكن استرجاع الملفات المحذوفة.',
};
const SHELL: Pair = {
  en: 'It wants to run a command on your computer. A command can change or delete anything you can.',
  ar: 'يريد تشغيل أمر على جهازك. يمكن للأمر تغيير أو حذف أي شيء تستطيع أنت تغييره.',
};
const WEB: Pair = {
  en: 'It wants to open a web address. Data can leave your computer in the request.',
  ar: 'يريد فتح عنوان على الويب. قد تغادر بيانات جهازك ضمن الطلب.',
};
const MCP: Pair = {
  en: 'It wants to use a connected tool. That tool can act outside this computer.',
  ar: 'يريد استخدام أداة متصلة. يمكن لهذه الأداة العمل خارج هذا الجهاز.',
};
const SECRET: Pair = {
  en: 'A program wants to use a stored secret such as a key. With it, it can act as you on other services.',
  ar: 'يريد برنامج استخدام سرّ محفوظ مثل مفتاح. به يستطيع التصرف باسمك في خدمات أخرى.',
};
const GENERIC: Pair = {
  en: 'An AI tool wants to do something Manar has not seen before. Approve only if you asked for it.',
  ar: 'تريد أداة ذكاء اصطناعي فعل شيء لم يره منار من قبل. وافق فقط إذا كنت قد طلبته.',
};

/** Extra sentences for commands that are risky in a way people do not see at a glance. */
const SHELL_FLAGS: { re: RegExp; text: Pair }[] = [
  {
    re: /\brm\s+(-[a-z]*[rf][a-z]*\s+)+/i,
    text: {
      en: 'This command deletes files for good.',
      ar: 'هذا الأمر يحذف الملفات نهائيا.',
    },
  },
  {
    re: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/i,
    text: {
      en: 'This command downloads a program and runs it at once.',
      ar: 'هذا الأمر ينزّل برنامجا ويشغله فورا.',
    },
  },
  {
    re: /\bsudo\b|\brunas\b/i,
    text: {
      en: 'This command runs with administrator rights.',
      ar: 'هذا الأمر يعمل بصلاحيات المسؤول.',
    },
  },
  {
    re: /\bgit\s+push\b[^\n]*(--force|-f\b)/i,
    text: {
      en: 'This command overwrites history on the remote repository.',
      ar: 'هذا الأمر يستبدل السجل في المستودع البعيد.',
    },
  },
  {
    re: /\bchmod\b|\bchown\b|\bicacls\b/i,
    text: {
      en: 'This command changes who can open files.',
      ar: 'هذا الأمر يغيّر من يستطيع فتح الملفات.',
    },
  },
];

function base(actionId: string): Pair {
  const a = actionId.toLowerCase();
  if (a === 'secret.use') return SECRET;
  if (/^(bash|shell|command)/.test(a)) return SHELL;
  if (/delete|remove/.test(a)) return DELETE;
  if (
    /^(edit|multiedit|write|notebookedit)/.test(a) ||
    /^file\.(write|edit)/.test(a)
  )
    return CHANGE;
  if (/^(read|glob|grep|ls|notebookread)/.test(a) || a.startsWith('file.read'))
    return READ;
  if (/^(webfetch|websearch)/.test(a)) return WEB;
  if (a.startsWith('mcp')) return MCP;
  return GENERIC;
}

export function explainRisk(
  actionId: string,
  resource: string,
  highRisk: boolean,
): RiskExplanation {
  const b = base(actionId);
  let { en, ar } = b;
  if (b === SHELL) {
    for (const f of SHELL_FLAGS) {
      if (f.re.test(resource)) {
        en += ' ' + f.text.en;
        ar += ' ' + f.text.ar;
      }
    }
  }
  if (highRisk) {
    en += ' This is high risk: decide it in the console.';
    ar += ' هذا الإجراء عالي الخطورة: قرّره من وحدة التحكم.';
  }
  return { en, ar };
}
