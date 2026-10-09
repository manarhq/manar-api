"""Aggregates every raw k6 sample of one run (all shards) into a Markdown report.

    python3 load/aggregate.py load/results/<run>

Percentiles are exact (nearest rank over all samples), not averages of the
per-shard summaries. Exit code 1 when an endpoint misses its target.
"""

import csv
import gzip
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

DECISION_EPS = {"authorize", "invoke_read", "mcp_call", "approval_create"}
MAX_ERROR_RATE = 0.01


def pct(sorted_values, p):
    if not sorted_values:
        return float("nan")
    return sorted_values[max(0, math.ceil(p * len(sorted_values)) - 1)]


def load(run):
    durations = defaultdict(list)  # ep -> [ms]
    failed = defaultdict(lambda: [0, 0])  # ep -> [failed, total]
    checks = defaultdict(lambda: [0, 0])  # check -> [passed, total]
    windows = defaultdict(lambda: defaultdict(list))  # minute -> ep -> [ms]
    window_fail = defaultdict(lambda: [0, 0])  # minute -> [failed, total]
    dropped = 0
    t0 = None
    for path in sorted(run.glob("shard-*.csv.gz")):
        with gzip.open(path, "rt", newline="") as fh:
            for row in csv.DictReader(fh):
                metric, value = row["metric_name"], float(row["metric_value"])
                ts = int(row["timestamp"])
                t0 = ts if t0 is None else min(t0, ts)
                ep = row.get("name") or ""
                if metric == "http_req_duration" and ep:
                    durations[ep].append(value)
                    windows[ts // 60][ep].append(value)
                elif metric == "http_req_failed" and ep:
                    failed[ep][0] += int(value)
                    failed[ep][1] += 1
                    if ep in DECISION_EPS:
                        window_fail[ts // 60][0] += int(value)
                        window_fail[ts // 60][1] += 1
                elif metric == "checks":
                    checks[row["check"]][0] += int(value)
                    checks[row["check"]][1] += 1
                elif metric == "dropped_iterations":
                    dropped += int(value)
    return durations, failed, checks, windows, window_fail, dropped, t0


def main():
    run = Path(sys.argv[1])
    targets = json.loads((Path(__file__).parent / "targets.json").read_text())
    durations, failed, checks, windows, window_fail, dropped, t0 = load(run)

    out = [f"## {run.name}", ""]
    host = run / "host.txt"
    if host.exists():
        out += ["```text", host.read_text().strip(), "```", ""]

    out += [
        "| Endpoint | Requests | p50 ms | p95 ms | p99 ms | max ms | Errors | Target p95/p99 | Met |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    missed = []
    for ep in targets:
        values = sorted(durations.get(ep, []))
        if not values:
            continue
        p95, p99 = pct(values, 0.95), pct(values, 0.99)
        f, n = failed[ep]
        err = f / n if n else 0.0
        t95, t99 = targets[ep]
        ok = p95 < t95 and p99 < t99 and err < MAX_ERROR_RATE
        if not ok:
            missed.append(ep)
        out.append(
            f"| {ep} | {len(values)} | {pct(values, 0.5):.1f} | {p95:.1f} | {p99:.1f} "
            f"| {values[-1]:.0f} | {100 * err:.2f}% | {t95}/{t99} | {'yes' if ok else 'no'} |"
        )

    out += ["", f"Dropped iterations (load generator could not keep the rate): {dropped}", ""]
    bad = {c: v for c, v in checks.items() if v[0] < v[1]}
    if bad:
        out += ["Failed checks:", ""]
        out += [f"- {c}: {v[1] - v[0]} of {v[1]} failed" for c, v in sorted(bad.items())]
        out.append("")

    # Per-minute view: decision throughput against authorize latency and
    # decision-path errors. The knee is where latency or errors turn up
    # while throughput stops following the offered load.
    out += [
        "| Minute | Decisions/s | authorize p95 ms | authorize p99 ms | invoke p95 ms | Decision errors |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for minute in sorted(windows):
        eps = windows[minute]
        n = sum(len(eps.get(e, [])) for e in DECISION_EPS)
        auth = sorted(eps.get("authorize", []))
        inv = sorted(eps.get("invoke_read", []))
        f, total = window_fail[minute]
        out.append(
            f"| {minute - t0 // 60} | {n / 60:.1f} | {pct(auth, 0.95):.1f} | {pct(auth, 0.99):.1f} "
            f"| {pct(inv, 0.95):.1f} | {100 * f / total if total else 0:.2f}% |"
        )
    out.append("")
    out.append("All targets met." if not missed else f"Targets missed: {', '.join(missed)}.")
    print("\n".join(out))
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
