import { CommandFactory } from 'nest-commander';

/** A command that throws (an unreachable database, a broken chain check) exits non-zero. */
export function failCommand(error: Error): never {
  console.error(error);
  process.exit(1);
}

/**
 * Commander's own exits (help, version, unknown option) keep their exit
 * code; anything else is a failure.
 */
export function failParse(error: Error & { exitCode?: number }): never {
  if (error.exitCode !== 0) console.error(error.message);
  process.exit(error.exitCode ?? 1);
}

/**
 * Runs the CLI. nest-commander's default handlers log a failed command and
 * leave the exit code at 0, so a restore drill or CI step would read a failed
 * `audit:verify` as a pass.
 */
export async function runCli(module: unknown): Promise<void> {
  await CommandFactory.run(module as never, {
    logger: ['warn', 'error', 'log'],
    errorHandler: failParse,
    serviceErrorHandler: failCommand,
  });
}
