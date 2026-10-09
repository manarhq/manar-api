import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    root: './',
    include: ['src/**/*.spec.ts'],
    coverage: {
      // Floor about 4 points under the 9 Oct 2026 measurement (statements
      // 64.2, branches 50.5, functions 59.7, lines 65.2). Raise it as
      // coverage grows; never lower it to make a pipeline pass.
      thresholds: { statements: 60, branches: 46, functions: 55, lines: 61 },
    },
  },
});
