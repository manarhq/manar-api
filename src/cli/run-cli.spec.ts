import { Module } from '@nestjs/common';
import { Command, CommandRunner } from 'nest-commander';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runCli } from './run-cli';

@Command({ name: 'boom' })
class BoomCommand extends CommandRunner {
  run(): Promise<void> {
    return Promise.reject(new Error('connect ECONNREFUSED 127.0.0.1:5432'));
  }
}

@Command({ name: 'ok' })
class OkCommand extends CommandRunner {
  run(): Promise<void> {
    return Promise.resolve();
  }
}

@Module({ providers: [BoomCommand, OkCommand] })
class TestCliModule {}

class Exit extends Error {
  constructor(readonly code: number | undefined) {
    super(`exit ${code}`);
  }
}

describe('runCli exit codes', () => {
  const argv = process.argv;
  afterEach(() => {
    process.argv = argv;
    vi.restoreAllMocks();
  });

  function exitCodeOf(command: string): Promise<number | undefined> {
    process.argv = ['node', 'cli', command];
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Exit(code as number | undefined);
    });
    return runCli(TestCliModule).then(
      () => undefined,
      (e: unknown) => {
        if (e instanceof Exit) return e.code;
        throw e;
      },
    );
  }

  it('a command that fails (for example an unreachable database) exits 1', async () => {
    expect(await exitCodeOf('boom')).toBe(1);
  });

  it('a command that succeeds does not exit with an error', async () => {
    expect(await exitCodeOf('ok')).toBeUndefined();
  });

  it('an unknown command exits non-zero', async () => {
    expect(await exitCodeOf('no-such-command')).toBe(1);
  });
});
