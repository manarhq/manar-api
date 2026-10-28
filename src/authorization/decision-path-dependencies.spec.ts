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

  /**
   * ADR-0002: the LLM proxy and its upstream client live in `agent-runtime/`
   * and must never become reachable from the PDP. Its config schema is the
   * one permitted module, for the same reason as `ai-advisory.config.ts`.
   */
  const LLM_CONFIG_ONLY = resolve(SRC, 'agent-runtime/llm-proxy.config.ts');

  it('cannot reach the LLM proxy or its upstream client', () => {
    const offenders = [...graph.keys()]
      .filter(
        (file) =>
          file.startsWith(resolve(SRC, 'agent-runtime')) &&
          file !== LLM_CONFIG_ONLY,
      )
      .map((f) => f.replace(`${SRC}/`, ''));
    expect(offenders).toEqual([]);
  });

  it('the one permitted agent-runtime module is a schema that imports nothing but zod', () => {
    const source = readFileSync(LLM_CONFIG_ONLY, 'utf8');
    expect([...source.matchAll(IMPORT_RE)].map((m) => m[1])).toEqual(['zod']);
  });

  /**
   * ADR-0008: the console assistant calls a model and reads through the
   * HTTP routes; nothing on the decision path may import any of it. No
   * module in it is exempt.
   */
  it('cannot reach the console assistant', () => {
    const offenders = [...graph.keys()]
      .filter((file) => file.startsWith(resolve(SRC, 'assistant')))
      .map((f) => f.replace(`${SRC}/`, ''));
    expect(offenders).toEqual([]);
  });

  it('the assistant module exists where this test looks for it', () => {
    // Guards against the check above passing vacuously after a rename.
    expect(existsSync(resolve(SRC, 'assistant/assistant.service.ts'))).toBe(
      true,
    );
  });

  /**
   * The decision metrics (src/metrics/metrics.ts) are on the path by design.
   * They must stay in-process counters: no first-party import that could
   * pull a network client or a new dependency onto the path.
   */
  it('the metrics module is reachable but imports no first-party module', () => {
    const metrics = resolve(SRC, 'metrics/metrics.ts');
    expect(graph.has(metrics)).toBe(true);
    const specifiers = [
      ...readFileSync(metrics, 'utf8').matchAll(IMPORT_RE),
    ].map((m) => m[1]);
    expect(specifiers.filter((s) => s?.startsWith('.'))).toEqual([]);
  });

  it('no module on the decision path calls fetch (the LLM upstream is HTTP)', () => {
    const offenders = [...graph.keys()]
      .filter((file) => /\bfetch\(/.test(readFileSync(file, 'utf8')))
      .map((f) => f.replace(`${SRC}/`, ''));
    expect(offenders).toEqual([]);
  });

  /**
   * Spec 7.2-7.3 (F4): the caches and the epoch store are on the path by design, and reach only
   * Valkey (node-redis through BoundedRedis) and OpenFGA. A Kafka, OpenSearch, gRPC or HTTP-client
   * import anywhere on the path would add a dependency the decision must not wait on.
   */
  it('the F4 cache modules are on the path, so the checks below mean something', () => {
    for (const f of [
      'kill-switches/kill-switch-epoch.service.ts',
      'common/redis/bounded-redis.ts',
      'authorization/openfga-client.service.ts',
    ]) {
      expect(graph.has(resolve(SRC, f)), f).toBe(true);
    }
  });

  it('the kill-switch epoch store imports Valkey access and nothing networked besides', () => {
    const specifiers = [
      ...readFileSync(
        resolve(SRC, 'kill-switches/kill-switch-epoch.service.ts'),
        'utf8',
      ).matchAll(IMPORT_RE),
    ].map((m) => m[1]);
    expect(specifiers.sort()).toEqual([
      '../audit/live/redis.config',
      '../common/redis/bounded-redis',
      '../config/env.validation',
      '@nestjs/common',
      '@nestjs/config',
    ]);
  });

  /**
   * The audit record is written in PostgreSQL by the decision; after the commit
   * `AuditService` hands the envelope to Kafka without awaiting it
   * (`this.kafkaPublisher.publish(envelope).catch(...)`), so the decision never waits on
   * Kafka. That publisher is the one permitted Kafka module on the path; the exemption is by
   * file name and the next test pins the call that justifies it.
   */
  const KAFKA_FIRE_AND_FORGET = resolve(
    SRC,
    'audit/kafka-publisher.service.ts',
  );
  const BANNED_PACKAGES =
    /kafka|@opensearch|@elastic|@grpc|@connectrpc|openai|@anthropic/i;

  it('nothing on the path imports a Kafka, OpenSearch or gRPC package, except the fire-and-forget audit publisher', () => {
    const offenders = [...graph.keys()]
      .filter((file) => file !== KAFKA_FIRE_AND_FORGET)
      .filter((file) =>
        [...readFileSync(file, 'utf8').matchAll(IMPORT_RE)].some(
          (m) =>
            !(m[1] ?? '.').startsWith('.') && BANNED_PACKAGES.test(m[1] ?? ''),
        ),
      );
    expect(offenders.map((f) => f.replace(`${SRC}/`, ''))).toEqual([]);
  });

  it('the pattern catches the real Kafka client and the exemption is still needed and still unawaited', () => {
    expect(BANNED_PACKAGES.test('@confluentinc/kafka-javascript')).toBe(true);
    expect(BANNED_PACKAGES.test('kafkajs')).toBe(true);
    expect(graph.has(KAFKA_FIRE_AND_FORGET)).toBe(true);
    expect(
      [...readFileSync(KAFKA_FIRE_AND_FORGET, 'utf8').matchAll(IMPORT_RE)].some(
        (m) => !(m[1] ?? '.').startsWith('.') && /kafka/i.test(m[1] ?? ''),
      ),
    ).toBe(true);
    const audit = readFileSync(resolve(SRC, 'audit/audit.service.ts'), 'utf8');
    expect(audit).toMatch(/this\.kafkaPublisher\.publish\(envelope\)\.catch\(/);
    expect(audit).not.toMatch(/await\s+this\.kafkaPublisher/);
  });

  it('the token lease store is not on the decision path (nothing calls it yet)', () => {
    expect(graph.has(resolve(SRC, 'rate-limit/token-lease.service.ts'))).toBe(
      false,
    );
  });
});
