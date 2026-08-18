import 'reflect-metadata';
import { CommandFactory } from 'nest-commander';
import { CliModule } from './cli/cli.module';

/**
 * Entry point for `pnpm manar <command>` (see package.json's "manar"
 * script). Separate from `src/main.ts` (the HTTP server) — see
 * src/cli/cli.module.ts.
 */
async function bootstrap(): Promise<void> {
  await CommandFactory.run(CliModule, ['warn', 'error', 'log']);
}

void bootstrap();
