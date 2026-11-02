import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { REQUIRED_ROLES_KEY } from '../auth/require-role.decorator';
import { DeviceTelemetryBody } from './data-collection.dto';
import { DataCollectionHostController } from './data-collection-host.controller';
import {
  DataCollectionController,
  WorkspaceDataPreferencesController,
} from './data-collection.controller';

const auth = (kind: string) =>
  ({
    issuer: 'i',
    tenant: { id: 't' },
    user: { keycloakSubject: 'u' },
    workspaceKind: kind,
  }) as never;
const at = new Date().toISOString();

describe('workspace data preferences', () => {
  const make = () => {
    const data = { getOrg: vi.fn(), setOrg: vi.fn() };
    return { data, c: new WorkspaceDataPreferencesController(data as never) };
  };
  it('403 outside company workspaces', () => {
    const { c, data } = make();
    expect(() => c.get(auth('PERSONAL'))).toThrow(ForbiddenException);
    expect(() => c.set(auth('SAMPLE'), { improveManar: false })).toThrow(
      ForbiddenException,
    );
    expect(data.setOrg).not.toHaveBeenCalled();
  });
  it('is restricted to owners and security admins', () => {
    expect(
      Reflect.getMetadata(
        REQUIRED_ROLES_KEY,
        WorkspaceDataPreferencesController,
      ),
    ).toEqual(['TENANT_OWNER', 'SECURITY_ADMIN']);
  });
  it('passes a valid patch and rejects unknown fields', () => {
    const { c, data } = make();
    void c.set(auth('COMPANY'), { aiTraining: false });
    expect(data.setOrg).toHaveBeenCalledWith('t', 'u', { aiTraining: false });
    expect(() => c.set(auth('COMPANY'), { name: 'x' })).toThrow();
  });
});

describe('POST /telemetry/events limits', () => {
  const make = () => {
    const data = { ingestConsole: vi.fn(() => Promise.resolve(1)) };
    return { data, c: new DataCollectionController(data as never) };
  };
  const ev = (over = {}) => ({ name: 'page_view', at, ...over });
  it('accepts a valid batch', async () => {
    const { c, data } = make();
    await c.events(auth('PERSONAL'), {
      events: [ev({ props: { a: 'x', b: 1, c: true } })],
    });
    expect(data.ingestConsole).toHaveBeenCalledOnce();
  });
  it('allows exactly the agreed names and rejects the retired ones', async () => {
    const ok = [
      'page_view',
      'sign_in_completed',
      'device_added',
      'first_approval_answered',
      'plan_changed',
      'client_error',
      'feature_used',
      'onboarding_step',
      'time_to_first_device',
    ];
    for (const name of ok) {
      const { c, data } = make();
      await c.events(auth('PERSONAL'), { events: [ev({ name })] });
      expect(data.ingestConsole).toHaveBeenCalledOnce();
    }
    for (const name of [
      'sign_in_done',
      'first_approval',
      'plan_change',
      'error_boundary',
    ]) {
      const { c } = make();
      await expect(
        c.events(auth('PERSONAL'), { events: [ev({ name })] }),
      ).rejects.toThrow();
    }
  });
  it.each([
    ['more than 50 events', { events: Array.from({ length: 51 }, () => ev()) }],
    ['an unknown event name', { events: [ev({ name: 'drop_table' })] }],
    [
      'a string over 200 chars',
      { events: [ev({ props: { a: 'x'.repeat(201) } })] },
    ],
    [
      'more than 20 keys',
      {
        events: [
          ev({
            props: Object.fromEntries(
              Array.from({ length: 21 }, (_, i) => [`k${i}`, 1]),
            ),
          }),
        ],
      },
    ],
    ['a nested object', { events: [ev({ props: { a: { b: 1 } } })] }],
  ])('rejects %s', async (_n, body) => {
    const { c, data } = make();
    await expect(c.events(auth('PERSONAL'), body)).rejects.toThrow();
    expect(data.ingestConsole).not.toHaveBeenCalled();
  });
});

describe('POST /host/v1/telemetry limits', () => {
  const host = (status = 'APPROVED') =>
    ({ tenantId: 't', ownerSubject: 'u', status }) as never;
  const body = (over = {}) => ({
    schema: 1,
    version: '1',
    os: 'linux',
    arch: 'amd64',
    events: [],
    samples: [],
    ...over,
  });
  const make = () => {
    const data = { ingestDevice: vi.fn(() => Promise.resolve(true)) };
    return { data, c: new DataCollectionHostController(data as never) };
  };
  it('accepts a valid batch and skips pending devices', async () => {
    const { c, data } = make();
    await c.telemetry(host(), body());
    expect(data.ingestDevice).toHaveBeenCalledOnce();
    await c.telemetry(host('PENDING'), body());
    expect(data.ingestDevice).toHaveBeenCalledOnce();
  });
  const sample = {
    kind: 'command',
    tool: 'claude',
    decision: 'ask',
    text: 'ls',
    at,
  };
  it.each([
    [
      '201 events',
      body({
        events: Array.from({ length: 201 }, () => ({ type: 'health', at })),
      }),
    ],
    ['51 samples', body({ samples: Array.from({ length: 51 }, () => sample) })],
    ['an unknown event type', body({ events: [{ type: 'keystrokes', at }] })],
    [
      'an unknown sample decision',
      body({ samples: [{ ...sample, decision: 'allow' }] }),
    ],
    ['a wrong schema version', body({ schema: 2 })],
    [
      'a body over 256 KB',
      body({
        samples: [
          { ...sample, text: 'x'.repeat(4000) },
          ...Array.from({ length: 49 }, () => ({
            ...sample,
            text: 'y'.repeat(4000),
          })),
        ],
        version: 'v'.repeat(70000),
      }),
    ],
  ])('rejects %s', async (_n, b) => {
    const { c, data } = make();
    await expect(c.telemetry(host(), b)).rejects.toThrow();
    expect(data.ingestDevice).not.toHaveBeenCalled();
  });
});

describe('edge-shaped batch', () => {
  const when = new Date().toISOString();
  it('is accepted by DeviceTelemetryBody (flattened keys, 3900-char stack, timing, two samples)', () => {
    const batch = {
      schema: 1,
      version: '0.9.0',
      os: 'linux',
      arch: 'amd64',
      events: [
        {
          type: 'health',
          at: when,
          data: {
            'decisions.warden.allow': 120,
            'decisions.warden.ask': 4,
            'decisions.jail.block': 2,
            cpu_pct: 3.5,
            uptime_s: 86400,
            first: true,
          },
        },
        {
          type: 'crash',
          at: when,
          data: { stack: 'x'.repeat(3900), signal: 'SIGSEGV' },
        },
        {
          type: 'timing',
          at: when,
          data: { 'warden.p50_ms': 2, 'warden.p95_ms': 9, 'jail.p50_ms': 1 },
        },
        { type: 'first_run', at: when },
      ],
      samples: [
        {
          kind: 'command',
          tool: 'claude-code',
          decision: 'ask',
          text: 'git push',
          at: when,
        },
        {
          kind: 'domain',
          tool: 'cursor',
          decision: 'block',
          text: 'example.com',
          at: when,
        },
      ],
    };
    expect(DeviceTelemetryBody.safeParse(batch).success).toBe(true);
  });
});
