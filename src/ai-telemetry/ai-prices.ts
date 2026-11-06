/**
 * What a model call costs us (performance program, decision 9): our own price table times the
 * tokens, reconciled monthly against the Azure bill. USD per 1,000,000 tokens, matched by model or
 * deployment name (longest prefix first, case-insensitive).
 *
 * Change a price by adding a new `version` and the new numbers together: every daily rollup row
 * records the version it was priced with, so history is never silently repriced. A model with no
 * entry costs 0 here and is counted as `unpricedCalls`, so the gap shows up instead of hiding.
 */
export interface ModelPrice {
  /** USD per 1M input tokens. */
  inputUsd: number;
  /** USD per 1M output tokens. */
  outputUsd: number;
}

export const AI_PRICE_TABLE = {
  version: '2026-11-05',
  currency: 'USD',
  /** List prices for the Azure OpenAI Global/Data Zone Standard tiers; review each quarter. */
  perMillionTokens: {
    'gpt-5-mini': { inputUsd: 0.25, outputUsd: 2 },
    'gpt-5-nano': { inputUsd: 0.05, outputUsd: 0.4 },
    'gpt-5': { inputUsd: 1.25, outputUsd: 10 },
    'gpt-4.1-mini': { inputUsd: 0.4, outputUsd: 1.6 },
    'gpt-4.1': { inputUsd: 2, outputUsd: 8 },
    'gpt-4o-mini': { inputUsd: 0.15, outputUsd: 0.6 },
    'gpt-4o': { inputUsd: 2.5, outputUsd: 10 },
    'claude-opus': { inputUsd: 15, outputUsd: 75 },
    'claude-sonnet': { inputUsd: 3, outputUsd: 15 },
    'claude-haiku': { inputUsd: 1, outputUsd: 5 },
  } satisfies Record<string, ModelPrice>,
  /** Providers we run ourselves: no per-token charge, so any model name costs 0 and counts as priced. */
  selfHostedProviders: ['ollama', 'vllm'] as readonly string[],
} as const;

const ENTRIES = Object.entries(AI_PRICE_TABLE.perMillionTokens).sort(
  (a, b) => b[0].length - a[0].length,
);

export function priceFor(
  provider: string,
  model: string,
): ModelPrice | undefined {
  if (AI_PRICE_TABLE.selfHostedProviders.includes(provider))
    return { inputUsd: 0, outputUsd: 0 };
  const m = model.toLowerCase();
  return ENTRIES.find(([prefix]) => m.startsWith(prefix))?.[1];
}

/** Cost in millionths of a US dollar (USD per 1M tokens equals micro-dollars per token). */
export function costMicros(
  provider: string,
  model: string,
  inputTokens: number,
  outputTokens: number,
): { micros: number; priced: boolean } {
  const price = priceFor(provider, model);
  if (!price) return { micros: 0, priced: false };
  return {
    micros: Math.round(
      inputTokens * price.inputUsd + outputTokens * price.outputUsd,
    ),
    priced: true,
  };
}
