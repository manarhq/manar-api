import type {
  PolicyContent,
  PolicyRule,
} from '../policy/policy-content.schema';
import { computeContentHash } from '../policy/policy-content-codec';

export const START_MODES = ['watch', 'ask', 'strict'] as const;
export type StartMode = (typeof START_MODES)[number];
export const DEFAULT_START_MODE: StartMode = 'ask';
/** The one policy per tenant whose latest published version is the active preset. */
export const START_MODE_POLICY_NAME = 'start-mode';

type Effect = PolicyRule['effect'];

/** Rules match any tool id: the catalogue (host.claude-code, host.cursor, ...) shares one preset. */
function rule(
  name: string,
  effect: Effect,
  resourcePattern: string,
  actionId = '*',
  toolId = '*',
): PolicyRule {
  return { name, toolId, actionId, resourcePattern, effect };
}

/**
 * Patterns are prefix-only. Secrets use the `secret-file:` and `~/` aliases from
 * `policy/resource-aliases.ts`. Commands are matched by their first words; a command that hides
 * the verb after `&&` or a pipe is not matched (the jail and the secrets watcher cover that).
 */
const deletes = (effect: Effect): PolicyRule[] =>
  [
    'rm *',
    'rm -*',
    'sudo rm*',
    'rmdir *',
    'del *',
    'rd *',
    'git clean*',
    'Remove-Item*',
  ].map((p) => rule(`Deleting files (${p.trim()})`, effect, p));

const forcePush = (effect: Effect): PolicyRule[] =>
  [
    'git push --force*',
    'git push -f*',
    'git push --delete*',
    'git push -d*',
  ].map((p) => rule(`Force pushes (${p})`, effect, p));

/** curl|sh-style downloads: any download command starts with one of these. */
const downloads = (effect: Effect): PolicyRule[] =>
  [
    'curl *',
    'wget *',
    'Invoke-WebRequest*',
    'iwr *',
    'irm *',
    'nc *',
    'scp *',
  ].map((p) => rule(`Downloads and uploads (${p.trim()})`, effect, p));

const ALLOW_REST = rule('Everything else runs and is recorded', 'ALLOW', '*');

export const START_MODE_PRESETS: Record<StartMode, PolicyContent> = {
  watch: { rules: [rule('Record everything, stop nothing', 'ALLOW', '*')] },
  ask: {
    rules: [
      rule('Secrets wait for you', 'APPROVAL_REQUIRED', 'secret-file:*'),
      rule(
        'Paths that climb out of their folder wait for you',
        'APPROVAL_REQUIRED',
        'unsafe-path:*',
      ),
      rule(
        'Commands the shell expands wait for you',
        'APPROVAL_REQUIRED',
        'unsafe-command:*',
      ),
      ...deletes('APPROVAL_REQUIRED'),
      ...forcePush('APPROVAL_REQUIRED'),
      ...downloads('APPROVAL_REQUIRED'),
      ALLOW_REST,
    ],
  },
  strict: {
    rules: [
      rule('Secrets are always blocked', 'DENY', 'secret-file:*'),
      rule(
        'Paths that climb out of their folder are blocked',
        'DENY',
        'unsafe-path:*',
      ),
      rule(
        'Commands the shell expands wait for you',
        'APPROVAL_REQUIRED',
        'unsafe-command:*',
      ),
      ...deletes('APPROVAL_REQUIRED'),
      ...forcePush('APPROVAL_REQUIRED'),
      ...downloads('APPROVAL_REQUIRED'),
      // Outside the project: the server does not see the project folder yet, so this is the
      // set of places a project is not: parent folders, system folders, dotfolders in home.
      ...[
        '../*',
        '..\\*',
        '/etc/*',
        '/usr/*',
        '/var/*',
        '/opt/*',
        '/bin/*',
        '/sbin/*',
        '/sys/*',
        '/proc/*',
        '/boot/*',
        '/root/*',
        '/private/*',
        'c:/windows/*',
        'c:/program files*',
        'c:/programdata/*',
        '~/.*',
      ].map((p) =>
        rule(`Outside the project folder (${p})`, 'APPROVAL_REQUIRED', p),
      ),
      rule('New websites wait for you', 'APPROVAL_REQUIRED', '*', 'webfetch'),
      ALLOW_REST,
    ],
  },
};

const HASH_TO_MODE = new Map<string, StartMode>(
  START_MODES.map((m) => [computeContentHash(START_MODE_PRESETS[m]), m]),
);

/** The preset a stored content hash belongs to, or `custom` when the user edited the rules. */
export function modeForContentHash(hash: string): StartMode | 'custom' {
  return HASH_TO_MODE.get(hash) ?? 'custom';
}
