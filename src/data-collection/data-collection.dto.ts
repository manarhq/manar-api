import { z } from 'zod';

/** Console event names the BFF may send. Anything else is a 400 (the client is out of date). */
export const CONSOLE_EVENTS = [
  'page_view',
  'sign_in_completed',
  'device_added',
  'first_approval_answered',
  'plan_changed',
  'client_error',
  'feature_used',
  'onboarding_step',
  'time_to_first_device',
] as const;

export const MAX_CONSOLE_EVENTS = 50;
export const MAX_DEVICE_EVENTS = 200;
export const MAX_DEVICE_SAMPLES = 50;
export const MAX_DEVICE_BODY_BYTES = 256 * 1024;

const prim = z.union([z.string(), z.number().finite(), z.boolean()]);
const key = z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/);
const when = z
  .string()
  .max(40)
  .refine((s) => !Number.isNaN(Date.parse(s)), 'invalid date');

/** Props of primitives only, at most 20 keys, strings at most `max` chars. */
const props = (keys: number, max: number) =>
  z
    .record(key, prim)
    .refine((o) => Object.keys(o).length <= keys, `at most ${keys} keys`)
    .refine(
      (o) =>
        Object.values(o).every((v) => typeof v !== 'string' || v.length <= max),
      `strings at most ${max} chars`,
    );

export const FlagsPatch = z
  .object({ improveManar: z.boolean(), aiTraining: z.boolean() })
  .partial()
  .strict();
export const MyPrefsPatch = z
  .object({
    improveManar: z.boolean(),
    aiTraining: z.boolean(),
    noticeDismissed: z.boolean(),
  })
  .partial()
  .strict();

export const ConsoleEventsBody = z
  .object({
    events: z
      .array(
        z.object({
          name: z.enum(CONSOLE_EVENTS),
          at: when,
          props: props(20, 200).optional(),
        }),
      )
      .max(MAX_CONSOLE_EVENTS),
  })
  .strict();

export const DeviceTelemetryBody = z
  .object({
    schema: z.literal(1),
    version: z.string().max(64),
    os: z.string().max(64),
    arch: z.string().max(32),
    events: z
      .array(
        z.object({
          type: z.enum(['first_run', 'crash', 'health', 'timing']),
          at: when,
          data: props(30, 4000).optional(),
        }),
      )
      .max(MAX_DEVICE_EVENTS),
    samples: z
      .array(
        z.object({
          kind: z.enum(['command', 'domain']),
          tool: z.string().max(64),
          decision: z.enum(['ask', 'block']),
          text: z.string().max(4000),
          at: when,
        }),
      )
      .max(MAX_DEVICE_SAMPLES)
      .default([]),
  })
  .strict();
