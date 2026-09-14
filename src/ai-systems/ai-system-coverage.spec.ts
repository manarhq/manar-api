import { describe, expect, it } from 'vitest';
import {
  DEFAULT_OBSERVATION_WINDOW_DAYS,
  deriveCoverage,
  type LinkedAgentObservation,
} from './ai-system-coverage';

/**
 * Release 2026-11-11 (brief §3.1). These tests pin the one property that
 * makes the coverage field worth showing at all: **it never claims
 * assurance the platform cannot demonstrate.** Each case is written around
 * a way that property could be violated in practice, not around a branch
 * of the implementation.
 */

const NOW = new Date('2026-09-08T12:00:00.000Z');

function daysAgo(days: number): Date {
  return new Date(NOW.getTime() - days * 24 * 60 * 60 * 1000);
}

function agent(
  overrides: Partial<LinkedAgentObservation> = {},
): LinkedAgentObservation {
  return {
    agentId: 'agent-1',
    status: 'ACTIVE',
    lastObservedAt: daysAgo(1),
    ...overrides,
  };
}

function derive(
  linkedAgents: LinkedAgentObservation[],
  overrides: {
    telemetryAvailable?: boolean;
    observationWindowDays?: number;
  } = {},
) {
  return deriveCoverage({
    telemetryAvailable: overrides.telemetryAvailable ?? true,
    linkedAgents,
    observationWindowDays:
      overrides.observationWindowDays ?? DEFAULT_OBSERVATION_WINDOW_DAYS,
    now: NOW,
  });
}

describe('deriveCoverage', () => {
  it('reports GOVERNED only when an ACTIVE agent has also been observed inside the window', () => {
    const result = derive([
      agent({ status: 'ACTIVE', lastObservedAt: daysAgo(2) }),
    ]);

    expect(result.coverage).toBe('GOVERNED');
    expect(result.activeLinkedAgentCount).toBe(1);
    expect(result.observedAgentCount).toBe(1);
    expect(result.lastObservedAt).toEqual(daysAgo(2));
  });

  it('reports DECLARED_ONLY for a freshly registered system with no linked agents', () => {
    const result = derive([]);

    expect(result.coverage).toBe('DECLARED_ONLY');
    expect(result.linkedAgentCount).toBe(0);
    expect(result.lastObservedAt).toBeNull();
  });

  it('reports DECLARED_ONLY when agents are linked but none has ever been observed', () => {
    // The failure this guards: someone fills in the form, links two
    // agents, and the console starts reporting the system as governed
    // purely because rows exist.
    const result = derive([
      agent({ agentId: 'a', lastObservedAt: null }),
      agent({ agentId: 'b', lastObservedAt: null }),
    ]);

    expect(result.coverage).toBe('DECLARED_ONLY');
    expect(result.linkedAgentCount).toBe(2);
    expect(result.activeLinkedAgentCount).toBe(2);
    expect(result.observedAgentCount).toBe(0);
  });

  it('reports DECLARED_ONLY when the only observations fall outside the window', () => {
    const result = derive([agent({ lastObservedAt: daysAgo(45) })], {
      observationWindowDays: 30,
    });

    expect(result.coverage).toBe('DECLARED_ONLY');
    expect(result.observedAgentCount).toBe(0);
    // No in-window observation, so there is no in-window timestamp to show.
    expect(result.lastObservedAt).toBeNull();
    // But the enforcement fact is still reported separately and truthfully.
    expect(result.activeLinkedAgentCount).toBe(1);
  });

  it('reports OBSERVED_ONLY when there is recent activity but no ACTIVE agent', () => {
    const result = derive([
      agent({ agentId: 'a', status: 'REVOKED', lastObservedAt: daysAgo(3) }),
      agent({ agentId: 'b', status: 'KILLED', lastObservedAt: daysAgo(10) }),
    ]);

    expect(result.coverage).toBe('OBSERVED_ONLY');
    expect(result.activeLinkedAgentCount).toBe(0);
    expect(result.observedAgentCount).toBe(2);
    expect(result.lastObservedAt).toEqual(daysAgo(3));
  });

  it('does not count a PENDING_ENROLLMENT agent as enforceable', () => {
    const result = derive([
      agent({ status: 'PENDING_ENROLLMENT', lastObservedAt: daysAgo(1) }),
    ]);

    expect(result.activeLinkedAgentCount).toBe(0);
    expect(result.coverage).toBe('OBSERVED_ONLY');
  });

  it('treats an unavailable telemetry source as MONITORING_UNAVAILABLE, never as absence of activity', () => {
    // The exact confusion this value exists to prevent: an OpenSearch or
    // database outage must not render as a calm "declared only" badge.
    const result = derive(
      [agent({ status: 'ACTIVE', lastObservedAt: daysAgo(1) })],
      { telemetryAvailable: false },
    );

    expect(result.coverage).toBe('MONITORING_UNAVAILABLE');
    expect(result.observedAgentCount).toBe(0);
    expect(result.lastObservedAt).toBeNull();
    // Declared facts are still reported — they did not become unknown.
    expect(result.linkedAgentCount).toBe(1);
    expect(result.activeLinkedAgentCount).toBe(1);
  });

  it('reports MONITORING_UNAVAILABLE even when nothing is linked, rather than DECLARED_ONLY', () => {
    const result = derive([], { telemetryAvailable: false });

    expect(result.coverage).toBe('MONITORING_UNAVAILABLE');
  });

  it('takes the latest observation across all linked agents', () => {
    const result = derive([
      agent({ agentId: 'a', lastObservedAt: daysAgo(9) }),
      agent({ agentId: 'b', lastObservedAt: daysAgo(2) }),
      agent({ agentId: 'c', lastObservedAt: daysAgo(5) }),
    ]);

    expect(result.lastObservedAt).toEqual(daysAgo(2));
    expect(result.observedAgentCount).toBe(3);
  });

  it('echoes the window back so a rendered verdict always carries what it was computed against', () => {
    const result = derive([agent()], { observationWindowDays: 7 });

    expect(result.observationWindowDays).toBe(7);
  });

  it('treats an observation exactly on the window boundary as in-window', () => {
    const result = derive([agent({ lastObservedAt: daysAgo(30) })], {
      observationWindowDays: 30,
    });

    expect(result.coverage).toBe('GOVERNED');
    expect(result.observedAgentCount).toBe(1);
  });

  it('mixes states correctly: one revoked-but-recent and one active-but-stale agent is still GOVERNED', () => {
    // Any ACTIVE agent plus any in-window observation is enough — the two
    // facts are deliberately not required to come from the same agent,
    // because a system commonly rotates agents.
    const result = derive([
      agent({ agentId: 'old', status: 'REVOKED', lastObservedAt: daysAgo(2) }),
      agent({ agentId: 'new', status: 'ACTIVE', lastObservedAt: null }),
    ]);

    expect(result.coverage).toBe('GOVERNED');
    expect(result.activeLinkedAgentCount).toBe(1);
    expect(result.observedAgentCount).toBe(1);
  });
});
