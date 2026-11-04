import { describe, expect, it, vi } from 'vitest';
import { UsagePausedError } from '../billing/usage-meter.service';
import { CloudMcpController } from './cloud-mcp.controller';

const request = {
  cloudAgent: {
    taskId: 'task-1',
    context: {
      tenant: { id: 't1', slug: 'acme' },
      agent: { id: 'a1', slug: 'c' },
    },
  },
};

function make(consume: (...a: unknown[]) => Promise<unknown>) {
  const serveMcp = vi.fn(() => Promise.resolve());
  const meter = { consume: vi.fn(consume) };
  const c = new CloudMcpController(
    {} as never,
    {} as never,
    { serveMcp } as never,
    {} as never,
    meter as never,
  );
  return { c, serveMcp, meter };
}

describe('cloud agents are billed per running minute', () => {
  it('meters one key per agent per UTC minute, then serves the call', async () => {
    const { c, serveMcp, meter } = make(() =>
      Promise.resolve({ source: 'allowance' }),
    );
    await c.mcp(request as never, {}, {} as never);
    expect(meter.consume).toHaveBeenCalledWith(
      't1',
      'cloud_minute',
      expect.stringMatching(/^cm:a1:\d{4}-\d\d-\d\dT\d\d:\d\d$/),
    );
    expect(serveMcp).toHaveBeenCalled();
  });

  it('a paused agent (no minutes, credits or cap left) is refused and never runs', async () => {
    const { c, serveMcp } = make(() =>
      Promise.reject(new UsagePausedError('credits_exhausted', 'u')),
    );
    await expect(
      c.mcp(request as never, {}, {} as never),
    ).rejects.toMatchObject({
      status: 402,
    });
    expect(serveMcp).not.toHaveBeenCalled();
  });

  it('a metering error refuses the call (deny on error)', async () => {
    const { c, serveMcp } = make(() => Promise.reject(new Error('db down')));
    await expect(c.mcp(request as never, {}, {} as never)).rejects.toThrow();
    expect(serveMcp).not.toHaveBeenCalled();
  });
});
