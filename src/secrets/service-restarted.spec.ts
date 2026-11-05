import { describe, expect, it } from 'vitest';
import { HostEventsBatchSchema } from './secrets.validation';

describe('service.restarted event', () => {
  it('is accepted with a bounded downtime and rejected otherwise', () => {
    const ev = { type: 'service.restarted', at: '2026-11-05T09:00:00Z' };
    expect(
      HostEventsBatchSchema.safeParse({
        events: [{ ...ev, downtimeSeconds: 7 }],
      }).success,
    ).toBe(true);
    for (const bad of [-1, 86_401, 1.5, '7'])
      expect(
        HostEventsBatchSchema.safeParse({
          events: [{ ...ev, downtimeSeconds: bad }],
        }).success,
      ).toBe(false);
  });
});
