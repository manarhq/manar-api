import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * ADR-004 and CLAUDE.md §12: the synchronous decision path touches PostgreSQL,
 * Redis and OpenFGA, and nothing else. manar-ai is named explicitly — "never
 * add manar-ai to the synchronous decision path".
 *
 * Phase 0 finding N1 was that it had been added anyway:
 * `authorization.service.ts` -> `RiskEngine.score()` ->
 * `await aiAdvisoryClient.analyzeRisk(...)`, putting a language model inside
 * the authorization decision.
 *
 * A comment saying "don't do this" does not survive a refactor. This test
 * walks the real static import graph from the PDP entry point and fails if the
 * advisory client becomes reachable again, which is the guarantee ADR-004
 * actually needs. Phase 1 exit criteria requires exactly this check.
 */

const SRC = resolve(__dirname, '..');
const ENTRY = resolve(__dirname, 'authorization.service.ts');

/** Resolve a relative import specifier to a real file on disk, or null. */
function resolveImport(fromFile: string, specifier: string): string | null {
  if (!specifier.startsWith('.')) return null; // node_modules / bare specifier
  const base = resolve(dirname(fromFile), specifier);
  for (const candidate of [
    `${base}.ts`,
    `${base}.tsx`,
    resolve(base, 'index.ts'),
    base,
  ]) {
    if (existsSync(candidate) && candidate.endsWith('.ts')) return candidate;
  }
  return null;
}

const IMPORT_RE =
  /(?:^|\n)\s*import\s+(?:type\s+)?[^'"]*from\s+['"]([^'"]+)['"]/g;

/** Every first-party module transitively reachable from `entry`. */
function reachableModules(entry: string): Map<string, string[]> {
  const seen = new Map<string, string[]>();
  const queue = [entry];
  const pathTo = new Map<string, string[]>([[entry, [entry]]]);

  while (queue.length > 0) {
    const file = queue.shift() as string;
    if (seen.has(file)) continue;
    const trail = pathTo.get(file) ?? [file];
    seen.set(file, trail);

    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(IMPORT_RE)) {
      const specifier = match[1];
      if (specifier === undefined) continue;
      const target = resolveImport(file, specifier);
      if (target === null || seen.has(target)) continue;
      pathTo.set(target, [...trail, target]);
      queue.push(target);
    }
  }
  return seen;
}

describe('ADR-004 — synchronous decision path dependencies', () => {
  const graph = reachableModules(ENTRY);

  it('walks a non-trivial graph, so a passing result means something', () => {
    // Guards against the walker silently resolving nothing and every
    // assertion below passing vacuously.
    expect(graph.size).toBeGreaterThan(10);
    expect([...graph.keys()].some((f) => f.includes('kill-switch'))).toBe(true);
  });

  /**
   * One module under `ai-advisory/` is legitimately reachable and must stay so:
   * `ai-advisory.config.ts` is a zod schema that the centralised
   * `config/env.validation.ts` aggregates alongside every other config module.
   * Reaching a config schema is not calling a service. The exclusion is
   * narrow and is itself asserted below, so it cannot be widened into a
   * loophole that readmits the client.
   */
  const CONFIG_ONLY = resolve(SRC, 'ai-advisory/ai-advisory.config.ts');

  it('cannot reach the manar-ai advisory client', () => {
    const offenders = [...graph.entries()].filter(
      ([file]) =>
        file.startsWith(resolve(SRC, 'ai-advisory')) && file !== CONFIG_ONLY,
    );

    const trail = (offenders[0]?.[1] ?? [])
      .map((f) => f.replace(`${SRC}/`, ''))
      .join('\n  -> ');
    expect(
      offenders.length,
      offenders.length === 0
        ? ''
        : `manar-ai is reachable from the PDP, violating ADR-004:\n  ${trail}`,
    ).toBe(0);
  });

  it('the one permitted ai-advisory module is a schema that imports nothing but zod', () => {
    // Justifies the exclusion above. Asserting on imports rather than on the
    // text, because the file's doc comments legitimately discuss
    // `AiAdvisoryClient` — describing a client is not depending on one. If
    // someone adds any import to slip a call past the previous assertion,
    // this fails.
    const source = readFileSync(CONFIG_ONLY, 'utf8');
    const specifiers = [...source.matchAll(IMPORT_RE)].map((m) => m[1]);

    expect(specifiers).toEqual(['zod']);
  });

  it('cannot reach the generated manar-ai gRPC client package', () => {
    const offenders = [...graph.keys()].filter((file) =>
      readFileSync(file, 'utf8').includes('@manar-ai/grpc-client'),
    );
    expect(offenders.map((f) => f.replace(`${SRC}/`, ''))).toEqual([]);
  });
});
