import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    root: './',
    include: ['src/**/*.spec.ts'],
    coverage: {
      // Every source file counts, tested or not, so an untested guard or
      // controller lowers the number. Left out on purpose: generated Prisma
      // clients, Nest module wiring, DTO shapes and the process entry points.
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.spec.ts',
        'src/generated/**',
        'src/**/*.module.ts',
        'src/**/*.dto.ts',
        'src/**/dto/**',
        'src/main.ts',
        'src/worker.main.ts',
        'src/cli.ts',
      ],
      // Floor about 4 points under the 9 Oct 2026 measurement over every
      // included file (statements 52.4, branches 50.5, functions 48.1, lines
      // 52.9). Raise it as coverage grows; never lower it to make a pipeline
      // pass.
      thresholds: { statements: 48, branches: 46, functions: 44, lines: 48 },
    },
  },
});
