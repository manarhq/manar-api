# Phase 7a: Demo SOC Tool Backends — Design

Status: Approved (autonomous execution)
Scope: new `packages/demo-soc-tools` workspace package in `manar-api`
(a standalone service — not proxied logic, a genuine separate backend
Manar's tool gateway will point at)
Depends on: nothing from Phase 6 — fully independent, runs in parallel
with Phase 7b (Tool Registry/Credential Broker/proxy execution)

## Purpose

Section 36: real, stateful demo SOC tool APIs — not frontend-only mocks.
Manar's tool gateway (Phase 7b) proxies real HTTP calls to this service;
its actions genuinely mutate its own deterministic in-memory/DB-backed
state, so "isolate host" really flips `isolated: false → true` and a
later `get-host` call reflects it.

## Service

A small Fastify (for consistency with `manar-api`'s own choice) service,
`packages/demo-soc-tools`, its own `main.ts`, own Dockerfile (multi-stage,
non-root, health check — mirror the conventions already established for
`manar-api`/`manar-ai`/`manar-web` in prior phases), added to
`deploy/docker-compose.yml`. Auth: a single static bearer token read from
env (`DEMO_TOOLS_API_KEY`) — this is deliberately simple; it's the
credential Phase 7b's `CredentialBrokerService` will fetch from OpenBao
and inject, never seen by any agent.

State: an in-memory store seeded deterministically at boot (Section 85's
demo entities belong to a later phase's seed data, but this service needs
its OWN internal state — e.g. a starting set of hosts/users/IPs/incidents
to act on). Reset endpoint (`POST /_demo/reset`, not auth-gated, dev-only
convenience) so tests and repeated demo runs start clean.

## Endpoints (Section 36)

All under a versioned prefix (e.g. `/v1`), all requiring the static
bearer token, all returning JSON:

**SIEM**

- `GET /v1/siem/events?query=...` — `search-events`, returns a
  deterministic filtered slice of seeded events.
- `GET /v1/siem/incidents/:id` — `fetch-incident`.

**EDR**

- `GET /v1/edr/hosts/:id` — `get-host` (returns current state incl.
  `isolated: boolean`).
- `POST /v1/edr/hosts/:id/isolate` — `isolate-host`, sets
  `isolated = true`.
- `POST /v1/edr/hosts/:id/release` — `release-host`, sets
  `isolated = false`.
- `POST /v1/edr/hosts/:id/processes/:pid/terminate` —
  `terminate-process`, removes/flags the process in that host's state.

**IAM**

- `GET /v1/iam/users/:id` — `get-user`.
- `POST /v1/iam/users/:id/disable` — `disable-user`, sets
  `enabled = false`.

**Firewall**

- `GET /v1/firewall/lookup?ip=...` — `lookup-ip`.
- `POST /v1/firewall/block` — `block-ip`, adds to a blocklist.
- `POST /v1/firewall/unblock` — `unblock-ip`, removes from it.

## Seed data

At minimum: workstation `WS-042` (not isolated, has a running process
implicated in `INC-2026-0042`), incident `INC-2026-0042` referencing
`WS-042` and a suspicious IP, a demo user account, and enough SIEM events
that `search-events` for `WS-042` returns something coherent. This seed
data will be reused by Phase 13's full demo scenario — name things
recognizably now so that phase doesn't need to invent new IDs.

## Testing

- Each endpoint: correct response shape, and for mutating endpoints,
  confirm the state change is visible on a subsequent `GET` (e.g.
  isolate → get-host shows `isolated: true`).
- Missing/invalid bearer token → 401 on every endpoint.
- `/_demo/reset` actually resets state (isolate a host, reset, get-host
  shows `isolated: false` again).
- Health endpoint(s) per the established convention from prior phases.

## Out of scope this phase

- Any connection to Manar's authorization/credential-broker pipeline —
  that's Phase 7b, which treats this service as an external HTTP tool
  it doesn't control.
- MCP protocol support (Phase 7b's demo MCP server, if any, is separate).
- Persistence beyond the process lifetime — in-memory state is
  intentional here, this is a demo fixture, not a product database.
