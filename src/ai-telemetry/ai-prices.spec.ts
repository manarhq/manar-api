import { describe, expect, it } from 'vitest';
import { priceOf } from '../ai-spend/pricing';
import { AI_PRICE_TABLE, costMicros, priceFor } from './ai-prices';

describe('AI price table', () => {
  it('is versioned and every price is a positive, finite number', () => {
    expect(AI_PRICE_TABLE.version).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(AI_PRICE_TABLE.currency).toBe('USD');
    for (const [model, p] of Object.entries(AI_PRICE_TABLE.perMillionTokens)) {
      expect(Number.isFinite(p.inputUsd) && p.inputUsd > 0, model).toBe(true);
      expect(Number.isFinite(p.outputUsd) && p.outputUsd > 0, model).toBe(true);
      expect(
        p.outputUsd,
        `${model}: output costs at least input`,
      ).toBeGreaterThanOrEqual(p.inputUsd);
    }
  });

  it('agrees with the device-spend estimate on every model both tables know', () => {
    for (const [model, p] of Object.entries(AI_PRICE_TABLE.perMillionTokens)) {
      const other = priceOf(model);
      expect(other, model).toBeDefined();
      expect([model, other?.in, other?.out]).toEqual([
        model,
        p.inputUsd,
        p.outputUsd,
      ]);
    }
  });

  it('prices 1M tokens in and out at exactly the table price (micro-dollars)', () => {
    expect(
      costMicros('azure_openai', 'gpt-5-mini', 1_000_000, 1_000_000),
    ).toEqual({
      micros: 2_250_000,
      priced: true,
    });
    expect(costMicros('azure_openai', 'gpt-5-mini', 1200, 300)).toEqual({
      micros: Math.round(1200 * 0.25 + 300 * 2),
      priced: true,
    });
  });

  it('matches the longest prefix and ignores case', () => {
    expect(priceFor('azure_openai', 'GPT-5-mini-2025-08-07')).toEqual({
      inputUsd: 0.25,
      outputUsd: 2,
    });
    expect(priceFor('azure_openai', 'gpt-5.1')).toEqual({
      inputUsd: 1.25,
      outputUsd: 10,
    });
  });

  it('reports an unknown hosted model as unpriced with zero cost, never as free or guessed', () => {
    expect(costMicros('azure_openai', 'mystery-9', 1000, 1000)).toEqual({
      micros: 0,
      priced: false,
    });
  });

  it('prices models we host ourselves at zero', () => {
    expect(costMicros('ollama', 'qwen3:8b', 5000, 5000)).toEqual({
      micros: 0,
      priced: true,
    });
  });
});
