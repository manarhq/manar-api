import { z } from 'zod';

/** Event types a device may send. The two `watch` types set the device's watcher status. */
export const SECRET_EVENT_TYPES = [
  'secret.touched',
  'secret.vault.stored',
  'secret.vault.released',
  'secret.vault.denied',
  'secret.watch.available',
  'secret.watch.unavailable',
] as const;

export const PATH_CLASSES = [
  'aws',
  'ssh',
  'azure',
  'gcloud',
  'kube',
  'docker',
  'browser',
  'env',
] as const;

const text = (max: number) =>
  z
    .string()
    .max(max)
    // eslint-disable-next-line no-control-regex
    .regex(/^[^\u0000-\u001f\u007f]*$/);

export const HostEventSchema = z
  .object({
    type: z.enum(SECRET_EVENT_TYPES),
    toolId: z
      .string()
      .regex(/^(host\.[a-z0-9-]{1,40}|other)$/)
      .optional(),
    process: text(128).optional(),
    pathClass: z.enum(PATH_CLASSES).optional(),
    maskedPath: text(1024).optional(),
    blocked: z.boolean().optional(),
    at: z.coerce.date(),
  })
  .strict();
export type HostEvent = z.infer<typeof HostEventSchema>;

export const HostEventsBatchSchema = z
  .object({ events: z.array(HostEventSchema).min(1).max(100) })
  .strict();

export const VAULT_KINDS = ['aws', 'ssh'] as const;
const ref = text(200).min(1);

export const VaultRequestSchema = z
  .object({ kind: z.enum(VAULT_KINDS), ref })
  .strict();

export const VaultReportSchema = z
  .object({
    kind: z.enum(VAULT_KINDS),
    ref,
    state: z.enum(['STORED', 'RESTORED', 'FAILED']),
    detail: text(300).optional(),
  })
  .strict();

export const AccessRequestSchema = z
  .object({
    kind: z.enum(VAULT_KINDS),
    ref,
    program: text(128).min(1),
    /** Full path of the requesting binary, home directory masked. */
    programPath: text(512).min(1),
    /** SHA-256 of the binary the device pinned and read. */
    programSha: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();

export const AccessDecisionSchema = z
  .object({
    decision: z.enum(['ALLOW_ONCE', 'ALLOW_8H', 'ALLOW_ALWAYS', 'DENY']),
  })
  .strict();

/**
 * The device masks the home directory itself; this is the second line: a path that still starts
 * with a home directory has its user name replaced.
 */
export function maskHome(path: string): string {
  return path.replace(
    /^(?:\/home\/[^/]+|\/Users\/[^/]+|\/root|[A-Za-z]:[\\/]+Users[\\/]+[^\\/]+)(?=[\\/]|$)/i,
    '~',
  );
}
