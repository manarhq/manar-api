import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { LlmBudgetStore } from './llm-budget.store';

/** Against the unit job's Redis (REDIS_URL), like the other store specs. */
const store = new LlmBudgetStore({
  get: (key: string) =>
    key === 'REDIS_URL'
      ? (process.env.REDIS_URL ?? 'redis://localhost:6379')
      : undefined,
} as unknown as ConfigService<AppConfig, true>);
afterAll(() => store.onModuleDestroy());

describe('LlmBudgetStore thinking signatures', () => {
  it('knows only the HMACs remembered for that tenant and task', async () => {
    const task = randomUUID();
    const expires = new Date(Date.now() + 60_000);
    expect(await store.knowsThinking('t1', task, ['a'])).toBe(false);
    await store.rememberThinking('t1', task, ['a', 'b'], expires);
    expect(await store.knowsThinking('t1', task, ['a', 'b'])).toBe(true);
    expect(await store.knowsThinking('t1', task, ['a', 'c'])).toBe(false);
    expect(await store.knowsThinking('t1', randomUUID(), ['a'])).toBe(false);
    expect(await store.knowsThinking('t2', task, ['a'])).toBe(false);
    expect(await store.knowsThinking('t1', task, [])).toBe(true);
  });
});
