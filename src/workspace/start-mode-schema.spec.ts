import { describe, expect, it } from 'vitest';
import { SetStartModeSchema } from './workspace.validation';

describe('one start-mode setting', () => {
  it('takes a mode, learning, or both; nothing else', () => {
    expect(SetStartModeSchema.safeParse({ mode: 'ask' }).success).toBe(true);
    expect(SetStartModeSchema.safeParse({ learning: 'off' }).success).toBe(
      true,
    );
    expect(
      SetStartModeSchema.safeParse({ mode: 'strict', learning: 'default' })
        .success,
    ).toBe(true);
    expect(SetStartModeSchema.safeParse({}).success).toBe(false);
    expect(SetStartModeSchema.safeParse({ learning: 'maybe' }).success).toBe(
      false,
    );
    expect(SetStartModeSchema.safeParse({ mode: 'ask', x: 1 }).success).toBe(
      false,
    );
  });
});
