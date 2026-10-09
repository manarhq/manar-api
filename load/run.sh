#!/usr/bin/env bash
# Runs one k6 profile against the dedicated load-test instance: one k6
# process per enrolled agent (k6 sends a single client certificate per
# process), then aggregates every raw sample into one report. Records disk
# and CPU pressure alongside (load/results/<run>/, gitignored).
#   load/run.sh smoke|steady|stress|soak     SHARDS=5 by default
set -euo pipefail
PROFILE="${1:-smoke}"
SHARDS="${SHARDS:-5}"
cd "$(dirname "$0")"
RUN="results/${PROFILE}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN"
K6_IMAGE="${K6_IMAGE:-grafana/k6:1.3.0}"

{
  echo "date: $(date -Is)"
  echo "host: $(hostname)  cpu: $(lscpu | sed -n 's/^Model name: *//p')  threads: $(nproc)"
  echo "memory: $(free -g | awk '/Mem:/{print $2" GiB total, "$7" GiB available"}')"
  echo "load average: $(cut -d' ' -f1-3 /proc/loadavg)"
  echo "docker root: $(docker info -f '{{.DockerRootDir}}') on $(df --output=source "$(docker info -f '{{.DockerRootDir}}')" | tail -1)"
  echo "api: $(git -C .. rev-parse --short HEAD) NODE_ENV=production, one process"
} > "$RUN/host.txt"

# Host pressure: per-device utilisation and await (iostat), CPU and run
# queue (vmstat), every 10 s.
iostat -dxm 10 > "$RUN/iostat.txt" &
IOSTAT=$!
vmstat -t 10 > "$RUN/vmstat.txt" &
VMSTAT=$!
# CPU and memory of the API process (API_PID) and of the backing containers.
PIDSTAT=
if [[ -n "${API_PID:-}" ]]; then
  pidstat -h -u -r -p "$API_PID" 10 > "$RUN/pidstat-api.txt" &
  PIDSTAT=$!
fi
while sleep 30; do
  docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' \
    manar-postgres manar-redis manar-openfga manar-keycloak 2>/dev/null | sed "s/^/$(date +%T) /"
done > "$RUN/docker-stats.txt" &
DSTATS=$!
trap 'kill $IOSTAT $VMSTAT $DSTATS $PIDSTAT 2>/dev/null || true' EXIT

pids=()
for ((i = 0; i < SHARDS; i++)); do
  docker run --rm --network host -u "$(id -u):$(id -g)" \
    -v "$PWD:/load" -w /load \
    -e PROFILE="$PROFILE" -e ONLY="${ONLY:-}" -e SHARD="$i" -e SHARDS="$SHARDS" -e OUT="$RUN" \
    -e API="${API:-http://127.0.0.1:3900}" -e MTLS_PORT="${MTLS_PORT:-3943}" \
    -e KEYCLOAK="${KEYCLOAK:-http://localhost:8081}" \
    "$K6_IMAGE" run --quiet --out "csv=$RUN/shard-$i.csv.gz" manar.js \
    > "$RUN/shard-$i.log" 2>&1 &
  pids+=($!)
done
# k6 exits 99 when a shard misses a threshold; the aggregate decides.
for p in "${pids[@]}"; do wait "$p" || true; done

python3 -I aggregate.py "$RUN" > "$RUN/report.md" && status=0 || status=$?
cat "$RUN/report.md"
exit $status
