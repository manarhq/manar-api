/**
 * The readiness *engine*: the pure, dependency-free half of
 * `GET /health/ready`.
 *
 * Deliberately split out of `ReadinessService` (which owns the Nest wiring
 * and the actual probe implementations) so the part that decides "does this
 * replica get traffic?" — the part whose bugs cause either an outage
 * (falsely unready) or black-holed requests (falsely ready) — is a set of
 * plain functions over plain data, testable exhaustively without a DI
 * container, a database, or a network. See `readiness.spec.ts`.
 *
 * Release 2026-11-11 reliability fix. `/health/ready` used to be a static
 * `{ status: 'ok' }` stub carrying a Phase-1 comment that said there was
 * nothing downstream to check yet — while being wired as the Kubernetes
 * `readinessProbe` (deploy/helm/manar-api/values.yaml) for a process that
 * by now has nine of them. A replica whose control database had gone away
 * therefore stayed in the Service's endpoint list and kept accepting
 * requests it could only 500.
 */

/** The hard per-probe time budget — see `runProbe`. */
export const DEFAULT_PROBE_TIMEOUT_MS = 2000;

/**
 * What one probe observed about one dependency.
 *
 * - `ok` — the probe completed successfully within its budget.
 * - `unhealthy` — the probe ran and *failed*. We know the dependency is
 *   not usable right now.
 * - `stale` — the probe did not finish inside its hard timeout, so this
 *   dependency's true state is unknown; the last thing we know about it is
 *   older than this probe cycle. Kept distinct from `unhealthy` on purpose:
 *   "the check timed out" and "the check came back negative" are different
 *   facts for whoever reads this body during an incident, and collapsing
 *   them hides the single most common cause of a slow readiness endpoint
 *   (a dependency that accepts connections but never answers).
 * - `degraded` — reachable but not fully functional. Reserved for probes
 *   that can distinguish partial from total failure.
 */
export type DependencyStatus = 'ok' | 'degraded' | 'stale' | 'unhealthy';

/** Overall readiness verdict — see `summarizeReadiness`. */
export type ReadinessStatus = 'ok' | 'degraded' | 'unhealthy';

export interface DependencyProbe {
  /** Stable machine-readable key in the response body (e.g. `ai-advisory`). */
  readonly name: string;
  /**
   * Whether this dependency being anything other than `ok` should take
   * this replica out of the Service's endpoint list.
   *
   * The bar for `true` is deliberately high: an unready replica serves no
   * traffic, so a dependency marked required is one whose loss makes this
   * process actively harmful to route to (it would 500 rather than
   * degrade). If every replica shares that dependency — and in this
   * deployment they all do — marking an optional dependency required turns
   * its outage into a *total* outage, plus a rolling readiness flap. See
   * `ReadinessService`'s probe list for the per-dependency reasoning.
   */
  readonly required: boolean;
  /** One line explaining what losing this dependency actually costs, echoed in the body for whoever is paged. */
  readonly impact: string;
  /**
   * Runs the check. Resolving means healthy; resolving with
   * `'degraded'` means reachable-but-impaired; rejecting means unhealthy.
   * Implementations do **not** need their own timeout — `runProbe` applies
   * the hard one.
   */
  run(): Promise<void | 'degraded'>;
}

export interface DependencyReport {
  status: DependencyStatus;
  required: boolean;
  impact: string;
  /** Wall-clock milliseconds the probe took, rounded — the number that tells you a dependency is dying before it is dead. */
  durationMs: number;
  /** Failure detail, present only when `status` is `unhealthy` or `stale`. */
  error?: string;
}

export interface ReadinessReport {
  /**
   * `ok` — everything healthy. `degraded` — every *required* dependency is
   * healthy but at least one optional one is not; this replica still takes
   * traffic. `unhealthy` — at least one required dependency is not healthy.
   */
  status: ReadinessStatus;
  /** The kubelet's actual signal: `false` means take this pod out of rotation. Always `true` for `ok` and `degraded`. */
  ready: boolean;
  checkedAt: string;
  dependencies: Record<string, DependencyReport>;
}

/**
 * Runs one probe under a **hard** timeout.
 *
 * This is the property that makes readiness safe to wire to a kubelet
 * probe at all: without it, a single dependency that accepts a TCP
 * connection and then never answers (a partitioned network, an overloaded
 * broker, a Postgres in recovery) makes the readiness *handler* hang, the
 * kubelet's own `timeoutSeconds` fire, and every replica flip unready at
 * once — the exact outage readiness exists to prevent. The timer is
 * `unref`'d so a pending probe timeout can never hold the process open
 * during shutdown.
 *
 * The losing side of the race is abandoned, not cancelled: nothing here can
 * cancel an in-flight query. That is fine and deliberate — the abandoned
 * promise's result is simply discarded, and its rejection is swallowed
 * explicitly below so an eventual late failure can never surface as an
 * unhandled rejection (which, under Node's default policy, would kill the
 * process — turning a slow dependency into the crash this whole fix exists
 * to prevent).
 */
export async function runProbe(
  probe: DependencyProbe,
  timeoutMs: number,
): Promise<DependencyReport> {
  const startedAt = Date.now();

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<'timed-out'>((resolve) => {
    timer = setTimeout(() => resolve('timed-out'), timeoutMs);
    timer.unref?.();
  });

  const attempt = probe.run().then(
    (outcome) => ({ kind: 'settled' as const, outcome }),
    (error: unknown) => ({ kind: 'failed' as const, error }),
  );

  try {
    const result = await Promise.race([attempt, timeout]);
    const durationMs = Date.now() - startedAt;

    if (result === 'timed-out') {
      // The abandoned attempt may still reject later; absorb it here so it
      // never becomes an unhandled rejection (see doc comment).
      void attempt.catch(() => undefined);
      return {
        status: 'stale',
        required: probe.required,
        impact: probe.impact,
        durationMs,
        error: `Probe exceeded its ${timeoutMs}ms budget; last known state is older than this check.`,
      };
    }

    if (result.kind === 'failed') {
      return {
        status: 'unhealthy',
        required: probe.required,
        impact: probe.impact,
        durationMs,
        error: describeError(result.error),
      };
    }

    return {
      status: result.outcome === 'degraded' ? 'degraded' : 'ok',
      required: probe.required,
      impact: probe.impact,
      durationMs,
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Runs every probe **concurrently** and folds the results into one report.
 *
 * Concurrent, not sequential, so the whole endpoint's worst case is one
 * probe budget rather than the sum of them — nine dependencies at 2s each
 * would otherwise blow past any sane kubelet `timeoutSeconds`.
 */
export async function evaluateReadiness(
  probes: readonly DependencyProbe[],
  timeoutMs: number = DEFAULT_PROBE_TIMEOUT_MS,
): Promise<ReadinessReport> {
  const results = await Promise.all(
    probes.map(
      async (probe) => [probe.name, await runProbe(probe, timeoutMs)] as const,
    ),
  );

  const dependencies: Record<string, DependencyReport> = {};
  for (const [name, report] of results) {
    dependencies[name] = report;
  }

  return {
    ...summarizeReadiness(dependencies),
    checkedAt: new Date().toISOString(),
    dependencies,
  };
}

/**
 * The actual readiness decision, isolated in one place.
 *
 * **Only a `required` dependency can make this replica unready.** An
 * optional dependency that is unhealthy, stale, or degraded downgrades the
 * overall `status` to `degraded` and is reported in full — but `ready`
 * stays `true`. That asymmetry is the whole point: the AI advisory service
 * (`src/ai-advisory/`) is optional by explicit design (Section 80 — an AI
 * outage must never change a deterministic authorization outcome, and every
 * one of its methods already returns `null` rather than throwing), so an
 * advisory outage must leave a perfectly serviceable deterministic profile
 * *serving*, flagged as degraded, and must never turn into a permanent
 * readiness failure that empties the Service's endpoint list.
 */
export function summarizeReadiness(
  dependencies: Record<string, DependencyReport>,
): { status: ReadinessStatus; ready: boolean } {
  const reports = Object.values(dependencies);
  const requiredUnhealthy = reports.some(
    (report) => report.required && report.status !== 'ok',
  );
  if (requiredUnhealthy) return { status: 'unhealthy', ready: false };

  const anyImpaired = reports.some((report) => report.status !== 'ok');
  return { status: anyImpaired ? 'degraded' : 'ok', ready: true };
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
