import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AUDIT_EVENT_TYPES } from '../audit-event-types';
import { mapAuditEventToOcsf, MappableAuditEvent } from './ocsf-mapper';
import { OCSF_SCHEMA_VERSION } from './ocsf-types';

function baseEvent(overrides: Partial<MappableAuditEvent>): MappableAuditEvent {
  return {
    id: randomUUID(),
    eventType: AUDIT_EVENT_TYPES.AGENT_ENROLLED,
    correlationId: randomUUID(),
    actor: { type: 'agent', id: 'agent-1' },
    timestamp: new Date('2026-08-19T00:00:00.000Z'),
    data: {},
    ...overrides,
  };
}

/**
 * Phase 9b (Section 50) — "OCSF-mapped output for a covered event type
 * matches the documented schema shape; an uncovered type is clearly
 * labeled as such, not silently forced into a wrong class."
 */
describe('mapAuditEventToOcsf', () => {
  it('pins the targeted OCSF schema version', () => {
    expect(OCSF_SCHEMA_VERSION).toBe('1.9.0');
  });

  it('maps agent.enrolled to Authentication [3002], Logon/Success', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({
        eventType: AUDIT_EVENT_TYPES.AGENT_ENROLLED,
        actor: { type: 'agent', id: 'agent-42' },
        data: { identifier: 'agent://acme/agent-42' },
      }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf.class_uid).toBe(3002);
    expect(result.ocsf.category_uid).toBe(3);
    expect(result.ocsf).toMatchObject({
      activity_id: 1,
      activity_name: 'Logon',
      status_id: 1,
      status: 'Success',
    });
    expect(
      (result.ocsf as { user: { uid: string; type: string } }).user,
    ).toEqual({
      uid: 'agent-42',
      type: 'agent',
    });
    expect(result.ocsf.metadata.version).toBe(OCSF_SCHEMA_VERSION);
    expect((result.ocsf as { unmapped: unknown }).unmapped).toMatchObject({
      identifier: 'agent://acme/agent-42',
    });
  });

  it('maps agent.enrollment_failed to Authentication [3002], Logon/Failure', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({ eventType: AUDIT_EVENT_TYPES.AGENT_ENROLLMENT_FAILED }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf).toMatchObject({
      class_uid: 3002,
      activity_id: 1,
      status_id: 2,
      status: 'Failure',
    });
  });

  it('maps agent.revoked to Authentication [3002], Logoff/Success', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({ eventType: AUDIT_EVENT_TYPES.AGENT_REVOKED }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf).toMatchObject({
      class_uid: 3002,
      activity_id: 2,
      activity_name: 'Logoff',
      status_id: 1,
    });
  });

  it('maps authorization.allowed to Authorize Session [3003] with status Success', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({
        eventType: AUDIT_EVENT_TYPES.AUTHORIZATION_ALLOWED,
        data: {
          taskId: 'task-1',
          toolId: 'siem',
          actionId: 'search',
          riskScore: 10,
        },
      }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf.class_uid).toBe(3003);
    expect(result.ocsf).toMatchObject({ status_id: 1, status: 'Success' });
    expect((result.ocsf as { privileges: string[] }).privileges).toEqual([
      'siem:search',
    ]);
    expect((result.ocsf as { session: { uid: string } }).session).toEqual({
      uid: 'task-1',
    });
    expect((result.ocsf as { unmapped: unknown }).unmapped).toMatchObject({
      riskScore: 10,
    });
  });

  it('maps authorization.denied to Authorize Session [3003] with status Failure', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({
        eventType: AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED,
        data: { taskId: 'task-1', reason: 'policy_denied' },
      }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf).toMatchObject({ status_id: 2, status: 'Failure' });
  });

  it('maps authorization.pending_approval to Authorize Session [3003] with status Unknown', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({
        eventType: AUDIT_EVENT_TYPES.AUTHORIZATION_PENDING_APPROVAL,
      }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf).toMatchObject({ status_id: 0, status: 'Unknown' });
  });

  it('maps tool.invocation.completed to API Activity [6003] with status Success', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({
        eventType: AUDIT_EVENT_TYPES.TOOL_INVOCATION_COMPLETED,
        data: { toolId: 'edr', actionId: 'isolate_host', resource: 'WS-017' },
      }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf.class_uid).toBe(6003);
    expect(result.ocsf).toMatchObject({ status_id: 1, status: 'Success' });
    expect(
      (result.ocsf as { api: { operation: string; service: { name: string } } })
        .api,
    ).toEqual({
      operation: 'isolate_host',
      service: { name: 'edr' },
    });
    expect((result.ocsf as { resources: { uid: string }[] }).resources).toEqual(
      [{ uid: 'WS-017' }],
    );
  });

  it('maps tool.invocation.failed to API Activity [6003] with status Failure, never guessing a CRUD activity_id', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({ eventType: AUDIT_EVENT_TYPES.TOOL_INVOCATION_FAILED }),
    );
    expect(result.mapped).toBe(true);
    if (!result.mapped) throw new Error('expected mapped result');
    expect(result.ocsf).toMatchObject({
      status_id: 2,
      status: 'Failure',
      activity_id: 0,
      activity_name: 'Unknown',
    });
  });

  it('leaves task.created clearly unmapped, with a real reason — never forced into a class', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({ eventType: AUDIT_EVENT_TYPES.TASK_CREATED }),
    );
    expect(result).toMatchObject({
      mapped: false,
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
    });
    if (result.mapped) throw new Error('expected unmapped result');
    expect(result.reason.length).toBeGreaterThan(10);
  });

  it('leaves approval.approved, policy.published, and audit.retention_executed clearly unmapped', () => {
    for (const eventType of [
      AUDIT_EVENT_TYPES.APPROVAL_APPROVED,
      AUDIT_EVENT_TYPES.POLICY_PUBLISHED,
      'audit.retention_executed',
    ]) {
      const result = mapAuditEventToOcsf(baseEvent({ eventType }));
      expect(result.mapped).toBe(false);
    }
  });

  it('never throws for an entirely unknown eventType, and reports it unmapped', () => {
    const result = mapAuditEventToOcsf(
      baseEvent({ eventType: 'something.nobody.registered' }),
    );
    expect(result).toMatchObject({
      mapped: false,
      eventType: 'something.nobody.registered',
    });
  });
});
