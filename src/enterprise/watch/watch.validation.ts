import { z } from 'zod';

/**
 * Bodies WATCH sends. Every object is strict: a field the schema does not name (a prompt, an
 * answer, a file) is refused, so no content can reach these routes by accident.
 */
const CATEGORY = z.enum([
  'national_id',
  'iban',
  'payment_card',
  'uae_mobile',
  'passport',
  'secret',
  'classified',
  'mip_label',
  'keyword',
  'source_code',
  'file_fingerprint',
]);
const HOST = z
  .string()
  .min(1)
  .max(253)
  .regex(/^[a-z0-9.-]+$/);

export const EnrolSchema = z
  .object({
    tenantId: z.uuid(),
    enrolKey: z.string().min(16).max(200),
    publicKeyJwk: z.record(z.string(), z.unknown()),
    profileEmail: z.email().max(320).nullable().optional(),
    browser: z.enum(['chrome', 'edge']),
    extensionVersion: z.string().max(32),
  })
  .strict();

export const HeartbeatSchema = z
  .object({
    extensionVersion: z.string().max(32),
    policyVersion: z.string().max(64).nullable(),
    configHash: z.string().regex(/^[0-9a-f]{64}$/),
    hints: z.object({ unpacked: z.boolean() }).strict(),
    /** { "2026-11-04": { "chatgpt.com": 3 } }: hostname-only counts. */
    visits: z
      .record(
        z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        z.record(HOST, z.number().int().min(0).max(100_000)),
      )
      .default({}),
  })
  .strict();

const EventSchema = z
  .object({
    clientEventId: z.uuid(),
    host: HOST,
    kind: z.enum(['send', 'file']),
    outcome: z.enum(['allow', 'allow_grant', 'would_block', 'block', 'flag']),
    ruleId: z.string().max(100).optional(),
    trace: z
      .array(
        z
          .object({
            ruleId: z.string().max(100),
            result: z.enum(['block', 'would_block', 'flag', 'granted']),
          })
          .strict(),
      )
      .max(100),
    counts: z.partialRecord(CATEGORY, z.number().int().min(0).max(1_000_000)),
    packVersion: z.string().max(32).optional(),
    at: z.iso.datetime(),
  })
  .strict();

export const EventsSchema = z
  .object({ events: z.array(EventSchema).min(1).max(200) })
  .strict();

export const NonceSchema = z.object({ redirectUri: z.url().max(300) }).strict();

export const IdentitySchema = z
  .object({ idToken: z.string().min(20).max(8192) })
  .strict();

export const PolicyQuerySchema = z.object({
  since: z.string().max(64).default(''),
  wait: z.coerce.number().int().min(0).max(25).default(0),
});
