import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HostAuthorizeSchema } from '../host-coverage/host-authorize.service';
import { HostEventsBatchSchema } from '../secrets/secrets.validation';
import { KNOWN_HOST_TOOL_IDS, hostActionRisk } from '../tools/host-actions';
import { redactForStorage } from './redact';

/**
 * host-contract.json is shared with manar-edge (testdata/contract/host-contract.json): what the
 * device sends must be what this API accepts and decides, and both redact stored commands alike.
 * CI checks the two copies are identical.
 */
interface Fixture {
  events: { edge: unknown; legacy: unknown };
  authorize: {
    cases: Array<{ body: Record<string, string> }>;
  };
  redact: { cases: Array<{ in: string; out: string }> };
}
const fx = JSON.parse(
  readFileSync(join(__dirname, 'host-contract.json'), 'utf8'),
) as Fixture;

describe('host contract (shared with manar-edge)', () => {
  it('accepts every events batch the device sends, current and 0.1.1', () => {
    for (const batch of [fx.events.edge, fx.events.legacy]) {
      const r = HostEventsBatchSchema.safeParse(batch);
      expect(r.success, JSON.stringify(r.error?.issues)).toBe(true);
    }
  });

  it('reads the 0.1.1 empty strings as absent fields', () => {
    const { events } = HostEventsBatchSchema.parse(fx.events.legacy);
    expect(events[0]).toMatchObject({ type: 'secret.watch.available' });
    expect(events[0]!.toolId).toBeUndefined();
    expect(events[0]!.pathClass).toBeUndefined();
    expect(events[0]!.maskedPath).toBeUndefined();
    expect(events.find((e) => e.process === 'ssh-add')?.pathClass).toBe('ssh');
    expect(
      events.find(
        (e) => e.process === 'cat' && e.type === 'secret.vault.denied',
      )?.pathClass,
    ).toBeUndefined();
  });

  it('decides every Claude Code hook call instead of denying it as unknown', () => {
    expect(fx.authorize.cases.length).toBeGreaterThan(0);
    for (const { body } of fx.authorize.cases) {
      const req = HostAuthorizeSchema.parse(body);
      expect(KNOWN_HOST_TOOL_IDS).toContain(req.toolId);
      expect(
        hostActionRisk(req.toolId, req.actionId.toLowerCase()),
        req.actionId,
      ).not.toBeNull();
      expect(req.caller).toMatch(/^uid:\d+\|s:[A-Za-z0-9._:-]{1,64}$/);
    }
  });

  it('redacts stored commands exactly as the device redacts telemetry', () => {
    expect(fx.redact.cases.length).toBeGreaterThan(0);
    for (const c of fx.redact.cases) {
      expect(redactForStorage(c.in), c.in).toBe(c.out);
    }
  });
});
