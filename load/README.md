# Load tests (k6)

Measures the agent decision path over mTLS with real enrolled agents, tool
execution, the governed MCP server, approvals, audit and the console's main
reads. Rerun before each release (PRODUCTION-BAR §5); results go in
`../docs/reports/LOAD-TEST-<date>.md` in the workspace.

Never run against the shared demo tenant: `setup.mjs` and `manar.js` refuse
`vax-security-ops-demo`. Use a dedicated API instance on its own ports, its own
Temporal task queues and its own OpenFGA store.

## Setup (once per stack)

```bash
# Dedicated instance (example ports; .env holds the rest of the local config)
PORT=3900 AGENT_MTLS_PORT=3943 METRICS_PORT=3990 \
TEMPORAL_TASK_QUEUE=manar-approvals-load WEBHOOK_DELIVERY_TASK_QUEUE=manar-webhooks-load \
OPENFGA_STORE_NAME=manar-load RATE_LIMIT_AGENT_LIMIT=1000000 RATE_LIMIT_HUMAN_LIMIT=1000000 \
  node --env-file=.env dist/main
WORKER_METRICS_PORT=3991 TEMPORAL_TASK_QUEUE=manar-approvals-load WEBHOOK_DELIVERY_TASK_QUEUE=manar-webhooks-load \
  node --env-file=.env dist/worker.main

# Own demo-soc-tools, so approved isolations never touch the shared fixture
(cd packages/demo-soc-tools && PORT=3910 node dist/main.js)

# Load tenant (users, tools, policies) and 10 agents with one task each
MANAR_SEED_TENANT_SLUG=p3-load MANAR_SEED_TENANT_NAME="Load Test" \
  node --env-file=.env dist/cli.js demo:seed --api-endpoint http://localhost:3900 \
  --demo-tools-base-url http://<host-ip>:3910
node load/setup.mjs            # LOAD_AGENTS=10, LOAD_API=http://localhost:3900
```

The rate limits are raised on the load instance so the test measures the
service, not the limiter (the limiter still runs on every request). With
`NODE_ENV=production`, loopback tool URLs are refused, so the tool fixture is
reached on the host's own address, listed in `SSRF_ALLOWED_HOSTS`.

`setup.mjs` writes `load/.identities/` (gitignored): each agent's certificate and
key, `agents.json` and a copy of the tenant credentials file.

## Run

```bash
API_PID=<api pid> load/run.sh smoke     # 60 s at 10 decisions/s
load/run.sh steady                      # 13 min: 10/s, a 50/s peak, back to 10/s
load/run.sh stress                      # 12 min: 50/s doubling up to 800/s
load/run.sh soak                        # 60 min at 25/s
ONLY=authorize load/run.sh smoke        # one scenario group
SHARDS=10 load/run.sh steady            # agents (k6 processes), default 5
```

k6 presents only the first `tlsAuth` certificate on every connection, so
`run.sh` starts one k6 process (Docker `grafana/k6:1.3.0`) per agent and divides
the rates. `aggregate.py` merges every raw sample (exact percentiles) into
`results/<run>/report.md`, with a per-minute table for finding the knee.
`iostat`, `vmstat`, `pidstat` (with `API_PID`) and `docker stats` samples are
stored next to it: report disk pressure with every number.

## Mix at the pilot peak (scale 1)

The pilot: 250,000 decisions a month (about 0.1/s on average) with peaks of 10
to 50 per second. Scale 1 is the 50/s peak.

| Group         | Requests/s | Endpoint                                                          |
| ------------- | ---------: | ----------------------------------------------------------------- |
| authorize     |         25 | `POST /agent/v1/authorize` (9 in 10 ALLOW, 1 in 10 DENY)          |
| invoke        |         15 | `POST /agent/v1/tools/invoke` siem.fetch-incident (executes)      |
| mcp_call      |          5 | MCP `tools/call` siem__fetch-incident                             |
| mcp_list      |          3 | MCP `tools/list`                                                  |
| approvals     |      1 + 1 | edr.isolate-host (202 pending), then `POST /approvals/:id/decide` |
| audit         |          2 | `GET /audit` list and a filtered search                           |
| console_pages |          5 | the console's main list reads; 1 in 25 is `GET /audit/verify`     |

## Targets (proposed, `targets.json`, milliseconds)

| Endpoint                          |  p95 |  p99 |
| --------------------------------- | ---: | ---: |
| authorize                         |  100 |  250 |
| mcp_list                          |  100 |  250 |
| invoke_read, mcp_call             |  300 |  800 |
| approval_create                   |  300 |  800 |
| approval_decide                   |  500 | 1500 |
| audit_list, audit_search, console |  300 |  800 |
| audit_verify                      | 1000 | 3000 |

Error rate under 1% per endpoint, and every decision check (right decision,
executed, pending) passing at 99.9%.
