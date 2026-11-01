/**
 * List-price estimates in US dollars per million tokens, matched by model-name prefix (longest
 * first). They are estimates: provider invoices win, and the console says so. A model with no
 * entry is counted as `unpriced` (cost 0) rather than guessed.
 * Review these against the providers' price pages before relying on a cap.
 */
const PRICES: ReadonlyArray<{ prefix: string; in: number; out: number }> = [
  { prefix: 'claude-opus', in: 15, out: 75 },
  { prefix: 'claude-sonnet', in: 3, out: 15 },
  { prefix: 'claude-haiku', in: 1, out: 5 },
  { prefix: 'gpt-5-mini', in: 0.25, out: 2 },
  { prefix: 'gpt-5-nano', in: 0.05, out: 0.4 },
  { prefix: 'gpt-5', in: 1.25, out: 10 },
  { prefix: 'gpt-4.1-mini', in: 0.4, out: 1.6 },
  { prefix: 'gpt-4.1', in: 2, out: 8 },
  { prefix: 'gpt-4o-mini', in: 0.15, out: 0.6 },
  { prefix: 'gpt-4o', in: 2.5, out: 10 },
  { prefix: 'o4-mini', in: 1.1, out: 4.4 },
  { prefix: 'o3', in: 2, out: 8 },
  { prefix: 'codex', in: 1.25, out: 10 },
  { prefix: 'gemini-2.5-flash', in: 0.3, out: 2.5 },
  { prefix: 'gemini-2.5-pro', in: 1.25, out: 10 },
  { prefix: 'gemini-3', in: 2, out: 12 },
  { prefix: 'gemini', in: 1.25, out: 10 },
].sort((a, b) => b.prefix.length - a.prefix.length);

export function priceOf(
  model: string,
): { in: number; out: number } | undefined {
  const m = model.toLowerCase();
  return PRICES.find((p) => m.startsWith(p.prefix));
}

export function isPriced(model: string): boolean {
  return priceOf(model) !== undefined;
}

/** Cost in millionths of a dollar: dollars per million tokens equals micro-dollars per token. */
export function costMicros(
  model: string,
  inputTokens: number,
  outputTokens: number,
): number {
  const p = priceOf(model);
  return p ? Math.round(inputTokens * p.in + outputTokens * p.out) : 0;
}
