/**
 * Release 2026-11-11 (brief §3.1) — deriving an `AiSystem`'s **runtime
 * coverage** from real observations.
 *
 * The rule this file exists to enforce is a truthfulness rule, not a
 * modelling preference: *a manually registered system is not automatically
 * covered by runtime enforcement.* Somebody filling in a form creates a
 * declaration. Whether Manar actually enforces anything for that system,
 * and whether Manar has actually seen it run, are separate facts that can
 * only be answered from `Agent.status` and real `ToolInvocation` rows.
 *
 * Coverage is therefore **never stored on `AiSystem`**. A stored column
 * would be correct on the day it was written and quietly wrong afterwards,
 * and the whole point of showing coverage in the UI is to stop the console
 * claiming assurance the platform cannot demonstrate. This module is a
 * pure function so the derivation itself is unit-testable without a
 * database (`ai-system-coverage.spec.ts`).
 *
 * The four values are the brief's own vocabulary. Their definitions here
 * are deliberately narrow, and each one is falsifiable from the inputs:
 *
 * | Value | Means |
 * | --- | --- |
 * | `GOVERNED` | At least one linked agent is `ACTIVE` (so its tool calls go through `CredentialBrokerService`'s authorization path) **and** at least one linked agent produced a `ToolInvocation` inside the observation window. Manar both enforces and sees this system. |
 * | `OBSERVED_ONLY` | A linked agent produced observations inside the window, but no linked agent is currently `ACTIVE`. Manar has evidence this system ran; it is not presently enforcing through any active principal named by this record. |
 * | `DECLARED_ONLY` | No linked agent produced any observation inside the window — including the common case of a record with no links at all. The record is a declaration and nothing more. |
 * | `MONITORING_UNAVAILABLE` | The observation source could not be consulted for this query. **Never** inferred from an empty result: silence and "we could not look" are different answers, and conflating them is exactly how a governance console ends up reporting healthy coverage during an outage. |
 *
 * Note what is *not* encoded here. An `ACTIVE` linked agent whose last
 * observation predates the window is `DECLARED_ONLY` by these rules even
 * though Manar would enforce it if it ran — that is intentional, because
 * the question this value answers is "does Manar have current evidence
 * about this system", and the enforcement fact is carried separately in
 * `activeLinkedAgentCount` rather than folded into one word. Callers that
 * need "would this be enforced if it ran" read that field; callers that
 * need "do we currently see it" read `coverage`.
 */

/** The brief §3.1 coverage vocabulary. See this file's doc comment for each value's exact meaning. */
export type AiSystemCoverage =
  'GOVERNED' | 'OBSERVED_ONLY' | 'DECLARED_ONLY' | 'MONITORING_UNAVAILABLE';

/** One linked agent, reduced to the only three facts the derivation uses. */
export interface LinkedAgentObservation {
  agentId: string;
  /** `Agent.status`. Only `ACTIVE` agents can actually transact through the credential broker. */
  status: 'PENDING_ENROLLMENT' | 'ACTIVE' | 'REVOKED' | 'KILLED';
  /**
   * The most recent `ToolInvocation.startedAt` for this agent, or `null`
   * when this agent has never been observed invoking anything. `null` is a
   * real answer ("never seen"), distinct from the source being
   * unavailable — which is `CoverageInput.telemetryAvailable`.
   */
  lastObservedAt: Date | null;
}

export interface CoverageInput {
  /**
   * `false` when the `ToolInvocation` query could not be performed at all
   * (database unavailable, query timed out). Forces
   * `MONITORING_UNAVAILABLE` regardless of everything else — see this
   * file's doc comment for why this must be an explicit input and can
   * never be inferred from an empty `linkedAgents`.
   */
  telemetryAvailable: boolean;
  linkedAgents: LinkedAgentObservation[];
  /** How far back an observation still counts as current. */
  observationWindowDays: number;
  /** Evaluation instant — injected rather than read from the clock so tests are deterministic. */
  now: Date;
}

/**
 * Everything the API returns about coverage. The counts and
 * `lastObservedAt` travel with the verdict on purpose: a single enum value
 * is not enough for an operator to judge whether they agree with it, and
 * the UI must be able to explain the verdict without a second round trip.
 */
export interface CoverageResult {
  coverage: AiSystemCoverage;
  /** How many agents are linked to this system at all (a declared fact). */
  linkedAgentCount: number;
  /** How many of those are `ACTIVE` — i.e. would be subject to enforcement if they ran now. */
  activeLinkedAgentCount: number;
  /** How many produced at least one observation inside the window. */
  observedAgentCount: number;
  /** The most recent observation across all linked agents, or `null` if there is none (or none inside the window). */
  lastObservedAt: Date | null;
  /** Echoed back so a rendered verdict always carries the window it was computed against. */
  observationWindowDays: number;
}

export const DEFAULT_OBSERVATION_WINDOW_DAYS = 30;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Derives coverage. Pure — no clock, no database, no configuration lookup.
 *
 * The `telemetryAvailable` check comes first and short-circuits, because
 * every subsequent branch would otherwise read an empty observation set as
 * evidence of absence.
 */
export function deriveCoverage(input: CoverageInput): CoverageResult {
  const linkedAgentCount = input.linkedAgents.length;
  const activeLinkedAgentCount = input.linkedAgents.filter(
    (agent) => agent.status === 'ACTIVE',
  ).length;

  if (!input.telemetryAvailable) {
    return {
      coverage: 'MONITORING_UNAVAILABLE',
      linkedAgentCount,
      activeLinkedAgentCount,
      // Deliberately zeroed/nulled rather than partially reported: the
      // source could not be consulted, so any observation figure would be
      // an artefact of a failed query rather than a measurement.
      observedAgentCount: 0,
      lastObservedAt: null,
      observationWindowDays: input.observationWindowDays,
    };
  }

  const windowStart = new Date(
    input.now.getTime() - input.observationWindowDays * MS_PER_DAY,
  );

  const observedInWindow = input.linkedAgents.filter(
    (agent) =>
      agent.lastObservedAt !== null && agent.lastObservedAt >= windowStart,
  );

  const lastObservedAt = observedInWindow.reduce<Date | null>(
    (latest, agent) => {
      const observed = agent.lastObservedAt as Date;
      return latest === null || observed > latest ? observed : latest;
    },
    null,
  );

  const base = {
    linkedAgentCount,
    activeLinkedAgentCount,
    observedAgentCount: observedInWindow.length,
    lastObservedAt,
    observationWindowDays: input.observationWindowDays,
  };

  if (observedInWindow.length === 0) {
    return { coverage: 'DECLARED_ONLY', ...base };
  }

  // At least one observation inside the window. Whether that amounts to
  // *governed* turns on whether any linked agent is currently in a state
  // where Manar's enforcement path applies to it at all.
  return {
    coverage: activeLinkedAgentCount > 0 ? 'GOVERNED' : 'OBSERVED_ONLY',
    ...base,
  };
}
