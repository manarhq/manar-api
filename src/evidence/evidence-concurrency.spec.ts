import { ConflictException, HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { EvidenceExportService } from './evidence-export.service';

/** An export that parks inside the dedicated snapshot read until released. */
function setup() {
  const gates: (() => void)[] = [];
  const tenants = {
    withDedicatedClient: () =>
      new Promise((_, reject) => gates.push(() => reject(new Error('stop')))),
  };
  const svc = new EvidenceExportService(
    {} as never,
    {} as never,
    {} as never,
    tenants as never,
  );
  const run = (tenantId: string) =>
    svc.export({} as never, tenantId, 'u', { since: new Date() });
  return { svc, run, gates };
}

describe('export concurrency', () => {
  it('a second export for the same workspace is refused with 409 export_already_running', async () => {
    const { run, gates } = setup();
    const first = run('t1').catch(() => undefined);
    const second = run('t1');
    await expect(second).rejects.toBeInstanceOf(ConflictException);
    await expect(second).rejects.toMatchObject({
      response: { reason: 'export_already_running' },
    });
    gates[0]!();
    await first;
    // The slot is free again.
    const third = run('t1').catch((e: Error) => e);
    gates[1]!();
    expect(((await third) as Error).message).toBe('stop');
  });

  it('a small global cap answers 429 for other workspaces', async () => {
    const { run, gates } = setup();
    const running = Array.from(
      { length: EvidenceExportService.MAX_CONCURRENT_EXPORTS },
      (_, i) => run(`t${i}`).catch(() => undefined),
    );
    const over = run('other');
    await expect(over).rejects.toBeInstanceOf(HttpException);
    await expect(over).rejects.toMatchObject({ status: 429 });
    gates.forEach((g) => g());
    await Promise.all(running);
  });

  it('a timed-out export frees its slot (bounded hold time)', async () => {
    let calls = 0;
    const svc = new EvidenceExportService(
      {} as never,
      {} as never,
      {} as never,
      {
        withDedicatedClient: () =>
          ++calls === 1
            ? Promise.reject(
                Object.assign(new Error('Transaction timeout'), {
                  code: 'P2028',
                }),
              )
            : new Promise(() => undefined),
      } as never,
    );
    const go = () => svc.export({} as never, 't1', 'u', { since: new Date() });
    await expect(go()).rejects.toThrow('Transaction timeout');
    void go(); // the slot was released, so this one starts instead of getting a 409
    await Promise.resolve();
    await expect(go()).rejects.toBeInstanceOf(ConflictException); // and now it is held again
  });

  it('one workspace cannot hold two global slots: its second try is a 409, not a slot', async () => {
    const { run, gates } = setup();
    const a = run('A').catch(() => undefined);
    await expect(run('A')).rejects.toBeInstanceOf(ConflictException);
    // The global cap still has room for the other workspaces.
    const others = Array.from(
      { length: EvidenceExportService.MAX_CONCURRENT_EXPORTS - 1 },
      (_, i) => run(`o${i}`).catch(() => undefined),
    );
    await expect(run('late')).rejects.toMatchObject({ status: 429 });
    gates.forEach((g) => g());
    await Promise.all([a, ...others]);
  });
});
