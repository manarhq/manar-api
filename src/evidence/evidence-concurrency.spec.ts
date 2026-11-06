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
});
