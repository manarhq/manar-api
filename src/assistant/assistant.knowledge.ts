/**
 * Curated, static text the console assistant can quote: what a reason code
 * means and how to do common things in the console. Written by people, not
 * generated, so it is the one source the assistant may present without a
 * tenant record behind it. EN and AR side by side; no em or en dashes.
 */

export type AssistantLocale = 'en' | 'ar';

interface Bilingual {
  en: string;
  ar: string;
}

export const REASON_CODES: Readonly<Record<string, Bilingual>> = {
  not_authorized: {
    en: 'The agent has no grant for this tool action in OpenFGA. The task does not allow it.',
    ar: 'لا يملك الوكيل صلاحية لهذا الإجراء في OpenFGA. المهمة لا تسمح به.',
  },
  forbidden_action: {
    en: 'The task lists this action as forbidden, so it is refused even if a grant exists.',
    ar: 'المهمة تصنف هذا الإجراء كإجراء ممنوع، لذلك يُرفض حتى مع وجود صلاحية.',
  },
  task_not_found: {
    en: 'The request named a task that does not exist in this workspace.',
    ar: 'الطلب أشار إلى مهمة غير موجودة في مساحة العمل هذه.',
  },
  not_assigned_agent: {
    en: 'The task belongs to a different agent. An agent can only act under its own tasks.',
    ar: 'المهمة مسندة إلى وكيل آخر. لا يعمل الوكيل إلا ضمن مهامه.',
  },
  task_not_live: {
    en: 'The task is not active: it has expired, been revoked or has not started.',
    ar: 'المهمة غير فعالة: انتهت صلاحيتها أو أُلغيت أو لم تبدأ بعد.',
  },
  task_status_revoked: {
    en: 'A person revoked the task, so nothing more can run under it.',
    ar: 'ألغى شخص المهمة، فلا يمكن تنفيذ أي شيء آخر ضمنها.',
  },
  task_outside_time_window: {
    en: 'The request came outside the time window the task allows.',
    ar: 'وصل الطلب خارج النافذة الزمنية التي تسمح بها المهمة.',
  },
  task_execution_limit_reached: {
    en: 'The task has used all the executions it was given.',
    ar: 'استهلكت المهمة كل مرات التنفيذ المسموح بها.',
  },
  policy_denied: {
    en: 'A published policy rule matched and its effect is DENY.',
    ar: 'تطابقت قاعدة في سياسة منشورة ونتيجتها الرفض.',
  },
  policy_requires_approval: {
    en: 'A published policy rule matched and requires a person to approve first.',
    ar: 'تطابقت قاعدة في سياسة منشورة وتتطلب موافقة شخص أولا.',
  },
  policy_evaluation_failed: {
    en: 'The policy could not be evaluated, so the request was refused (fail closed).',
    ar: 'تعذر تقييم السياسة، فرُفض الطلب احتياطيا.',
  },
  policy_load_failed: {
    en: 'The published policy could not be loaded, so the request was refused (fail closed).',
    ar: 'تعذر تحميل السياسة المنشورة، فرُفض الطلب احتياطيا.',
  },
  risk_ceiling_exceeded: {
    en: "The deterministic risk score is above the task's risk ceiling, so a person must approve.",
    ar: 'درجة المخاطر المحسوبة أعلى من سقف المخاطر للمهمة، لذلك يلزم موافقة شخص.',
  },
  approval_required: {
    en: 'The action is held until a person with the Approver role decides.',
    ar: 'الإجراء معلق حتى يقرر شخص لديه دور الموافق.',
  },
  platform_kill_switch_active: {
    en: 'The platform kill switch is on. Every agent action is stopped.',
    ar: 'مفتاح الإيقاف على مستوى المنصة مفعل. كل إجراءات الوكلاء متوقفة.',
  },
  tenant_kill_switch_active: {
    en: 'The kill switch for this workspace is on. Every agent action here is stopped.',
    ar: 'مفتاح الإيقاف لمساحة العمل هذه مفعل. كل إجراءات الوكلاء فيها متوقفة.',
  },
  agent_kill_switch_active: {
    en: "This agent's kill switch is on. It cannot act until a person turns it off.",
    ar: 'مفتاح الإيقاف لهذا الوكيل مفعل. لا يمكنه العمل حتى يطفئه شخص.',
  },
  agent_group_kill_switch_active: {
    en: 'The kill switch of a group this agent belongs to is on.',
    ar: 'مفتاح الإيقاف لمجموعة ينتمي إليها هذا الوكيل مفعل.',
  },
  tool_kill_switch_active: {
    en: "This tool's kill switch is on. No agent can use it right now.",
    ar: 'مفتاح الإيقاف لهذه الأداة مفعل. لا يمكن لأي وكيل استخدامها الآن.',
  },
  kill_switch_active: {
    en: 'A kill switch that covers this request is on.',
    ar: 'مفتاح إيقاف يشمل هذا الطلب مفعل.',
  },
  ai_system_suspended: {
    en: 'The AI system this agent belongs to is suspended, so its agents are blocked.',
    ar: 'نظام الذكاء الاصطناعي الذي ينتمي إليه الوكيل معلق، فوكلاؤه محظورون.',
  },
  ai_system_retired: {
    en: 'The AI system this agent belongs to is retired, so its agents are blocked.',
    ar: 'نظام الذكاء الاصطناعي الذي ينتمي إليه الوكيل متقاعد، فوكلاؤه محظورون.',
  },
  agent_not_active: {
    en: 'The agent is not active (for example still pending enrollment).',
    ar: 'الوكيل غير فعال (مثلا ما زال بانتظار التسجيل).',
  },
  agent_terminated: {
    en: 'The agent was revoked or killed and can no longer act.',
    ar: 'أُلغي الوكيل أو أُوقف نهائيا ولم يعد بإمكانه العمل.',
  },
  enforcement_dependency_unavailable: {
    en: 'A service Manar needs to decide safely (database, Redis, OpenFGA or audit store) was unavailable, so the request was refused (fail closed).',
    ar: 'كانت خدمة يحتاجها منار لاتخاذ القرار بأمان غير متاحة (قاعدة البيانات أو Redis أو OpenFGA أو سجل التدقيق)، فرُفض الطلب احتياطيا.',
  },
  authorization_backend_unavailable: {
    en: 'OpenFGA could not be reached, so the request was refused (fail closed).',
    ar: 'تعذر الوصول إلى OpenFGA، فرُفض الطلب احتياطيا.',
  },
  dlp_policy_violation: {
    en: 'Data loss prevention found a credential or sensitive data in the request and blocked it.',
    ar: 'اكتشفت حماية البيانات بيانات اعتماد أو بيانات حساسة في الطلب فحظرته.',
  },
  sensitive_data_detected: {
    en: 'Data loss prevention found sensitive data and blocked or redacted it.',
    ar: 'اكتشفت حماية البيانات بيانات حساسة فحظرتها أو حجبتها.',
  },
  tool_disabled: {
    en: 'The tool is disabled in the tool registry.',
    ar: 'الأداة معطلة في سجل الأدوات.',
  },
  tool_not_found: {
    en: 'The request named a tool that is not registered.',
    ar: 'الطلب أشار إلى أداة غير مسجلة.',
  },
  tool_action_not_found: {
    en: 'The tool has no action with that name.',
    ar: 'لا يوجد إجراء بهذا الاسم في الأداة.',
  },
  grant_expired: {
    en: 'The approval grant expired before the agent used it.',
    ar: 'انتهت صلاحية الموافقة قبل أن يستخدمها الوكيل.',
  },
  grant_already_consumed: {
    en: 'The approval grant is single use and was already used.',
    ar: 'الموافقة تستخدم مرة واحدة وقد استُخدمت بالفعل.',
  },
  grant_mismatch: {
    en: 'The agent tried to use an approval for different parameters than the ones approved.',
    ar: 'حاول الوكيل استخدام موافقة بمعطيات مختلفة عن التي تمت الموافقة عليها.',
  },
  grant_revoked: {
    en: 'The approval grant was revoked.',
    ar: 'أُلغيت الموافقة.',
  },
  grant_not_found: {
    en: 'The approval grant the agent presented does not exist.',
    ar: 'الموافقة التي قدمها الوكيل غير موجودة.',
  },
  grant_invalid: {
    en: 'The approval grant the agent presented is not valid.',
    ar: 'الموافقة التي قدمها الوكيل غير صالحة.',
  },
  llm_budget_exhausted: {
    en: 'The task used its whole model token budget.',
    ar: 'استهلكت المهمة كامل رصيدها من رموز النموذج.',
  },
  llm_upstream_unavailable: {
    en: 'The language model provider did not answer.',
    ar: 'لم يستجب مزود النموذج اللغوي.',
  },
};

export const HELP_TOPICS: Readonly<
  Record<string, { title: Bilingual; steps: Bilingual; href: string }>
> = {
  add_agent: {
    title: { en: 'Add a new agent', ar: 'إضافة وكيل جديد' },
    steps: {
      en: '1. Open Agents and choose New agent. 2. Enter a slug and a display name, then register. 3. Open the agent and generate a one-time enrollment token. 4. Give the token to whoever runs the agent; the agent enrolls with a certificate signing request and gets its own identity. 5. Create a task for it under Tasks so it can act. Needs Security Admin or Tenant Owner.',
      ar: '1. افتح الوكلاء واختر وكيل جديد. 2. أدخل المعرف المختصر والاسم ثم سجّل. 3. افتح الوكيل وأنشئ رمز تسجيل لمرة واحدة. 4. سلّم الرمز لمن يشغّل الوكيل، فيسجّل الوكيل بطلب توقيع شهادة ويحصل على هويته. 5. أنشئ له مهمة من صفحة المهام ليتمكن من العمل. يتطلب دور مسؤول الأمن أو مالك مساحة العمل.',
    },
    href: '/agents',
  },
  create_task: {
    title: { en: 'Give an agent a task', ar: 'إسناد مهمة إلى وكيل' },
    steps: {
      en: '1. Open Tasks and choose New task. 2. Pick the agent, add the tool actions it may use and a resource pattern. 3. Set the expiry, risk ceiling and the maximum number of executions. 4. Create. The agent can only do what the task allows, until it expires.',
      ar: '1. افتح المهام واختر مهمة جديدة. 2. اختر الوكيل وأضف إجراءات الأدوات المسموح بها ونمط الموارد. 3. حدد وقت الانتهاء وسقف المخاطر وعدد مرات التنفيذ. 4. أنشئ المهمة. لا يستطيع الوكيل إلا ما تسمح به المهمة وحتى انتهائها.',
    },
    href: '/tasks',
  },
  approve_action: {
    title: {
      en: 'Approve or deny a held action',
      ar: 'الموافقة على إجراء معلق أو رفضه',
    },
    steps: {
      en: '1. Open Approvals. 2. Open the request and read the exact parameters, the risk breakdown and why approval is needed. 3. Write a reason and choose Approve or Deny. The grant is single use and bound to those parameters; Manar checks everything again when the agent uses it. Needs the Approver role.',
      ar: '1. افتح الموافقات. 2. افتح الطلب واقرأ المعطيات الدقيقة وتفصيل المخاطر وسبب الحاجة للموافقة. 3. اكتب السبب واختر موافقة أو رفض. الموافقة تستخدم مرة واحدة ومرتبطة بهذه المعطيات، ويعيد منار التحقق عند استخدامها. يتطلب دور الموافق.',
    },
    href: '/approvals',
  },
  kill_switch: {
    title: {
      en: 'Stop an agent with a kill switch',
      ar: 'إيقاف وكيل بمفتاح الإيقاف',
    },
    steps: {
      en: 'Kill switches exist for the platform, the workspace, an agent group, an agent and a tool. Open the agent (or tool) and turn its kill switch on; every new action is refused at once with a kill switch reason. Turning it off is a separate, audited step. Needs Security Admin or Tenant Owner.',
      ar: 'توجد مفاتيح إيقاف للمنصة ومساحة العمل ومجموعة الوكلاء والوكيل والأداة. افتح الوكيل أو الأداة وفعّل مفتاح الإيقاف، فيُرفض كل إجراء جديد فورا. الإطفاء خطوة منفصلة ومسجلة. يتطلب دور مسؤول الأمن أو مالك مساحة العمل.',
    },
    href: '/agents',
  },
  change_policy: {
    title: { en: 'Change a policy rule', ar: 'تعديل قاعدة في سياسة' },
    steps: {
      en: '1. Open Policies and the policy. 2. Create a new version with the changed rules; drafts change nothing. 3. A Security Admin or Tenant Owner publishes it. Only the published version is used for decisions, and every decision records the policy version it used.',
      ar: '1. افتح السياسات ثم السياسة. 2. أنشئ نسخة جديدة بالقواعد المعدلة، والمسودات لا تغير شيئا. 3. ينشرها مسؤول الأمن أو مالك مساحة العمل. لا تُستخدم في القرارات إلا النسخة المنشورة، وكل قرار يسجل نسخة السياسة التي استخدمها.',
    },
    href: '/policies',
  },
  register_tool: {
    title: { en: 'Register a tool', ar: 'تسجيل أداة' },
    steps: {
      en: "Tools are the connectors Manar executes on the agent's behalf. Open Tools to see the registered tools and their actions. Each action has a risk level and data classification; agents never hold the tool credentials, Manar does.",
      ar: 'الأدوات هي الموصلات التي ينفذ منار من خلالها نيابة عن الوكيل. افتح الأدوات لرؤية الأدوات المسجلة وإجراءاتها. لكل إجراء مستوى مخاطر وتصنيف بيانات، ولا يحمل الوكلاء بيانات اعتماد الأدوات بل يحملها منار.',
    },
    href: '/tools',
  },
  audit_and_evidence: {
    title: {
      en: 'Check the audit log and export evidence',
      ar: 'مراجعة سجل التدقيق وتصدير الأدلة',
    },
    steps: {
      en: 'Open Audit to search events by agent, task, decision or time. Verify chain checks the hash chain for tampering. Export evidence builds a signed bundle that anyone can verify later. Needs Auditor, Security Admin or Tenant Owner.',
      ar: 'افتح التدقيق للبحث في الأحداث حسب الوكيل أو المهمة أو القرار أو الوقت. التحقق من السلسلة يكشف أي عبث في سلسلة التجزئة. تصدير الأدلة ينشئ حزمة موقعة يمكن لأي أحد التحقق منها لاحقا. يتطلب دور المدقق أو مسؤول الأمن أو مالك مساحة العمل.',
    },
    href: '/audit',
  },
  roles: {
    title: { en: 'Who can do what', ar: 'من يستطيع ماذا' },
    steps: {
      en: 'Tenant Owner and Security Admin manage agents, tasks, tools, kill switches and publish policies. AI Governance Manager drafts policies and manages AI systems. Approver decides held actions. Auditor reads the audit log and evidence. SOC Operator and Read Only see less. Roles are granted under Users.',
      ar: 'مالك مساحة العمل ومسؤول الأمن يديران الوكلاء والمهام والأدوات ومفاتيح الإيقاف وينشران السياسات. مدير حوكمة الذكاء الاصطناعي يصيغ السياسات ويدير أنظمة الذكاء الاصطناعي. الموافق يقرر في الإجراءات المعلقة. المدقق يقرأ سجل التدقيق والأدلة. مشغل مركز العمليات والقراءة فقط يرون أقل. تُمنح الأدوار من صفحة المستخدمين.',
    },
    href: '/users',
  },
  how_decisions_work: {
    title: { en: 'How Manar decides', ar: 'كيف يقرر منار' },
    steps: {
      en: 'Every agent action is checked in order: kill switches, the task (assigned, live, not forbidden, within limits), the OpenFGA grant, the published policy rules, then a deterministic risk score against the task ceiling. The answer is ALLOW, APPROVAL_REQUIRED or DENY with a reason code. No language model takes part in the decision; AI advice is shown to approvers only.',
      ar: 'يُفحص كل إجراء للوكيل بالترتيب: مفاتيح الإيقاف، ثم المهمة (مسندة وفعالة وغير ممنوعة وضمن الحدود)، ثم صلاحية OpenFGA، ثم قواعد السياسة المنشورة، ثم درجة مخاطر محسوبة مقابل سقف المهمة. النتيجة ALLOW أو APPROVAL_REQUIRED أو DENY مع رمز السبب. لا يشارك أي نموذج لغوي في القرار، ونصائح الذكاء الاصطناعي تُعرض على الموافقين فقط.',
    },
    href: '/overview',
  },
};

export const HELP_TOPIC_KEYS = Object.keys(HELP_TOPICS) as [
  string,
  ...string[],
];
