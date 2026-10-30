import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';

/**
 * The first-run screen flips from "Waiting" to Approve on the live feed (`GET /events/live`,
 * which streams every tenant audit event to TENANT_OWNER). It needs `host.registered` when the
 * device enrols and `host.approved` after approval, so both must stay audited events and the
 * feed must stay open to the owner role.
 */
describe('live feed carries host events', () => {
  it('registration and approval are audited event types', () => {
    expect(AUDIT_EVENT_TYPES.HOST_REGISTERED).toBe('host.registered');
    expect(AUDIT_EVENT_TYPES.HOST_APPROVED).toBe('host.approved');
  });

  it('the live feed is readable by the workspace owner and is not filtered by event type', () => {
    const src = readFileSync(
      join(__dirname, '../audit/live/live-events.controller.ts'),
      'utf8',
    );
    expect(src).toMatch(/RequireRole\([^)]*'TENANT_OWNER'/);
    expect(src).not.toMatch(/eventType\s*[!=]==?/);
  });
});
