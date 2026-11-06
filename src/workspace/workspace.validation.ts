import { z } from 'zod';
import { START_MODES } from './start-mode.presets';

/** One setting: the mode Manar applies, and whether new devices learn for 7 days first. */
export const SetStartModeSchema = z
  .object({
    mode: z.enum(START_MODES).optional(),
    learning: z.enum(['on', 'off', 'default']).optional(),
  })
  .strict()
  .refine((v) => v.mode !== undefined || v.learning !== undefined, {
    message: 'send a mode, learning, or both',
  });
