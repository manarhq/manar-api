import { z } from 'zod';
import { START_MODES } from './start-mode.presets';

export const SetStartModeSchema = z
  .object({ mode: z.enum(START_MODES) })
  .strict();
