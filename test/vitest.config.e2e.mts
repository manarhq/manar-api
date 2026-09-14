import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    root: './',
    include: ['**/*.e2e-spec.ts'],
    hookTimeout: 30000,

    /**
     * Release 2026-11-11 — run e2e spec files one at a time.
     *
     * Vitest parallelises across files by default, which is right for the
     * unit suite and wrong for this one: every file here shares a single
     * set of real backing services — one Postgres, one Redis, one Keycloak,
     * one OpenSearch, one Kafka, one demo-soc-tools. Several tests assert
     * on *global* state in those services, and cannot be correct while
     * another file is mutating it concurrently:
     *
     *  - `app-hardening-webhooks.e2e-spec.ts` asserts that one tenant's
     *    burst does not exhaust another tenant's rate-limit budget. Those
     *    counters live in the shared Redis, so a concurrent file issuing
     *    requests changes the answer.
     *  - the audit-search and indexing specs assert on documents present in
     *    the shared OpenSearch index.
     *  - `tool-gateway-demo-integration.e2e-spec.ts` asserts that a
     *    specific host is isolated in the shared demo-soc-tools process.
     *
     * Observed behaviour before this change: 164/168 passing with a
     * *different* set of roughly four failures on each run, every one of
     * which passed when its file was run alone. That is the signature of
     * shared-state contention, not of broken code — but a suite whose
     * failures move between runs cannot gate a release, because nobody can
     * tell a real regression from the noise.
     *
     * The cost is wall-clock time. That is the right trade: these tests
     * exist to be trusted, and most of their runtime is per-file setup
     * against real services rather than assertions.
     */
    fileParallelism: false,
  },
});
