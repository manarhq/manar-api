import { describe, expect, it, vi } from 'vitest';
import { UsageMeterService } from '../billing/usage-meter.service';
import { AuditController } from '../audit/audit.controller';
import { IncidentsController } from '../incidents/incidents.controller';
import { PolicyController } from '../policy/policy.controller';
import { AssistantController } from '../assistant/assistant.controller';
import type { AuthContext } from '../auth/auth-context';
import { EventEmitter } from 'node:events';

/**
 * The four AI endpoints a workspace can reach with "Allow external AI" off answer politely,
 * before anything is metered, read or sent to a model.
 */
const auth = {
  tenant: { id: 't1', slug: 't1' },
  user: { id: 'u1', keycloakSubject: 'u1', email: '', displayName: '' },
  roles: ['TENANT_OWNER'],
} as unknown as AuthContext;

function meter() {
  const m = Object.create(UsageMeterService.prototype) as UsageMeterService;
  const consume = vi.fn().mockResolvedValue(undefined);
  Object.assign(m, { consume, release: vi.fn() });
  return { m, consume };
}
const tenants = { getClient: vi.fn().mockResolvedValue({}) };
const offGate = { aiGate: vi.fn().mockResolvedValue('switched_off') };

describe('AI endpoints with the switch off', () => {
  it('POST /incidents/summarize', async () => {
    const { m, consume } = meter();
    const incidents = { summarizeIncident: vi.fn() };
    const c = new IncidentsController(
      incidents as never,
      tenants as never,
      m,
      offGate as never,
    );
    const out = await c.summarize(auth, { description: 'x' });
    expect(out).toMatchObject({ available: false, reason: 'ai_switched_off' });
    expect(consume).not.toHaveBeenCalled();
    expect(incidents.summarizeIncident).not.toHaveBeenCalled();
  });

  it('POST /audit/investigate', async () => {
    const { m, consume } = meter();
    const search = { investigateAudit: vi.fn() };
    const c = new AuditController(
      {} as never,
      search as never,
      tenants as never,
      {} as never,
      {} as never,
      {} as never,
      m,
      offGate as never,
    );
    const out = await c.investigate(auth, { question: 'who did what?' });
    expect(out).toMatchObject({ available: false, reason: 'ai_switched_off' });
    expect(consume).not.toHaveBeenCalled();
    expect(search.investigateAudit).not.toHaveBeenCalled();
  });

  it('POST /policies/suggest', async () => {
    const { m, consume } = meter();
    const policies = { suggestPolicy: vi.fn() };
    const c = new PolicyController(
      policies as never,
      tenants as never,
      m,
      offGate as never,
      {} as never,
    );
    const out = await c.suggestPolicy(auth, {
      naturalLanguageDescription: 'deny deletes',
      policyName: 'p',
    });
    expect(out).toMatchObject({
      available: false,
      reason: 'ai_switched_off',
      version: null,
    });
    expect(consume).not.toHaveBeenCalled();
    expect(policies.suggestPolicy).not.toHaveBeenCalled();
  });

  it('POST /assistant/chat', async () => {
    const { m, consume } = meter();
    const assistant = { chat: vi.fn() };
    const catalog = { externalAiSwitchedOff: vi.fn().mockResolvedValue(true) };
    const c = new AssistantController(assistant as never, m, catalog as never);
    const out = await c.chat(auth, 'Bearer t', { messages: [] });
    expect(out).toEqual({ available: false, reason: 'ai_switched_off' });
    expect(consume).not.toHaveBeenCalled();
    expect(assistant.chat).not.toHaveBeenCalled();
  });

  it('the streaming and background variants answer politely too, and start nothing', async () => {
    class FakeRaw extends EventEmitter {
      chunks: string[] = [];
      writableEnded = false;
      socket = { setNoDelay: vi.fn() };
      writeHead = vi.fn();
      write(c: string) {
        this.chunks.push(c);
      }
      end() {
        this.writableEnded = true;
      }
    }
    const reply = (raw: FakeRaw) => ({ hijack: vi.fn(), raw }) as never;
    const done = (raw: FakeRaw) => raw.chunks.join('');

    const { m, consume } = meter();
    const incidents = { summarizeIncident: vi.fn() };
    const r1 = new FakeRaw();
    await new IncidentsController(
      incidents as never,
      tenants as never,
      m,
      offGate as never,
    ).summarizeStream(auth, { description: 'x' }, reply(r1));
    expect(done(r1)).toContain('event: done');
    expect(done(r1)).toContain('ai_switched_off');

    const search = { investigateAudit: vi.fn() };
    const r2 = new FakeRaw();
    await new AuditController(
      {} as never,
      search as never,
      tenants as never,
      {} as never,
      {} as never,
      { auditSearchFloor: vi.fn().mockResolvedValue(null) } as never,
      m,
      offGate as never,
    ).investigateStream(auth, { question: 'who did what?' }, reply(r2));
    expect(done(r2)).toContain('ai_switched_off');

    const assistant = { chat: vi.fn() };
    const catalog = { externalAiSwitchedOff: vi.fn().mockResolvedValue(true) };
    const r3 = new FakeRaw();
    await new AssistantController(
      assistant as never,
      m,
      catalog as never,
    ).chatStream(auth, 'Bearer t', { messages: [] }, reply(r3));
    expect(done(r3)).toContain('ai_switched_off');

    const suggestJobs = { start: vi.fn() };
    const out = await new PolicyController(
      {} as never,
      tenants as never,
      m,
      offGate as never,
      suggestJobs as never,
    ).startSuggestJob(auth, {
      naturalLanguageDescription: 'deny deletes',
      policyName: 'p',
    });
    expect(out).toMatchObject({
      available: false,
      reason: 'ai_switched_off',
      job: null,
    });

    expect(consume).not.toHaveBeenCalled();
    expect(incidents.summarizeIncident).not.toHaveBeenCalled();
    expect(search.investigateAudit).not.toHaveBeenCalled();
    expect(assistant.chat).not.toHaveBeenCalled();
    expect(suggestJobs.start).not.toHaveBeenCalled();
  });

  it('with the switch on, the action is metered and the feature runs', async () => {
    const { m, consume } = meter();
    const assistant = { chat: vi.fn().mockResolvedValue({ available: true }) };
    const catalog = { externalAiSwitchedOff: vi.fn().mockResolvedValue(false) };
    const c = new AssistantController(assistant as never, m, catalog as never);
    await c.chat(auth, 'Bearer t', { messages: [] });
    expect(consume).toHaveBeenCalledOnce();
    expect(assistant.chat).toHaveBeenCalledOnce();
  });
});
