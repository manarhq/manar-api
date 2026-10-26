# Manar edge: the agent's network path

The contract is `manar-edge/docs/design.md` (sections 1, 2 and 4 are this repo's part). This page
describes what manar-api does and how to run it. Code: `src/edge/`, `src/tools/host-actions.ts`.

An agent on a governed host reaches two things only: Manar's agent listener and the hostnames an
admin allowed for it. The host binary (`manar-edge`) builds the jail; the gateway
(`manar-edge-gateway`, namespace `manar-gateway`) holds the WireGuard peers and the egress proxy;
manar-api decides which peers exist, whether each is active or cut, and which hosts each may reach.

## Configuration

| Variable                        | Default         | Notes                                                                                                                               |
| ------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `MANAR_EDGE_ENABLED`            | `false`         | Off: enrollment with `edge` answers 400 `edge_not_enabled`, `/internal/v1/edge/*` answers 404.                                      |
| `MANAR_EDGE_CIDR`               | `100.88.0.0/16` | Overlay network. The gateway is the first host (`100.88.0.1`); peers get `/32` addresses from the second host up.                   |
| `MANAR_EDGE_ENDPOINT`           |                 | `<host>:51820`, handed to hosts at enrollment. Required when enabled.                                                               |
| `MANAR_EDGE_GATEWAY_PUBLIC_KEY` |                 | The gateway's WireGuard public key (base64, 32 bytes). Required when enabled.                                                       |
| `MANAR_EDGE_GATEWAY_TOKEN`      |                 | Secret, at least 32 characters (OpenBao `kv/prod/manar-edge` `gateway_token`). Required when enabled.                               |
| `MANAR_AGENTS_HOST`             |                 | Host name of the agent mTLS listener, returned as `manarServerName` (the SNI hosts send through the tunnel). Required when enabled. |

All are validated at startup (`src/edge/edge.config.ts`). In the chart, the non-secret ones are in
`config`, the token in `secrets.data` (or the externally managed Secret), and
`networkPolicy.ingress.edge-gateway.enabled: true` admits the gateway pods
(`manar-gateway` / `app.kubernetes.io/name=manar-edge-gateway`) on the agent mTLS port (relay) and
the HTTP port (sync API).

## Enrollment

`POST /agents/enroll` takes an optional `edge: { wgPublicKey }`. These are refused before the
enrollment token is spent:

- edge off: 400 `{ code: "edge_not_enabled" }`;
- not canonical base64 of 32 bytes: 400;
- a token that does not verify (unknown, used, expired, terminal agent, or not the agent it
  names; checked read-only, not consumed): the uniform 401, before any token is spent or
  certificate signed;
- the key belongs to another agent, or the agent has no peer and no address is free: 409, checked
  only after the token verifies and scoped to that agent, so an unauthenticated caller learns
  nothing about keys or the address pool.

If the edge step still fails after the certificate is signed (a race the read-only check could not
see), that certificate is revoked before the answer (audited as `agent.enrollment_failed`,
reason `edge_failed`), so no live certificate exists that was never handed out. The token is spent
then; a person issues a new one.

After the certificate is issued, the agent's peer is created (cut, `enrolling`, then refreshed), or
replaced on re-enrollment (new key, same peer id and address: one peer per agent), and the response carries the `edge` object of the
contract (`peerId`, `address`, `gatewayPublicKey`, `gatewayEndpoint`, `manarAddress`,
`manarServerName`, `proxyAddress`, `keepaliveSeconds`). The host tool `host.claude-code` is
registered in the tenant at the same time (see below).

Address allocation runs under the global edge lock (the `edge_state` row), takes the lowest address
no `edge_peers` row holds, and a unique index backs it, so two enrollments at once, on any replica,
in any tenant, never get the same address. Rows are not deleted while their tenant exists, so an
address is never reused while a row holds it.

## Peer state

`edge_peers` (control database) is the platform registry the gateway reads. It is a projection: the
tenant database stays the source of truth. `EdgePeerService` recomputes a peer from it and writes
`state`, `cutReason` and `allowHosts`.

How a refresh runs: it takes a ticket per peer (`refreshSeq + 1`), then reads the control and
tenant databases outside any lock. Tenants are read in parallel (8 at a time) and peers within a
tenant 4 at a time, each peer's read under its own 2.5 s timeout. A read that times out or fails
cuts that peer only (`enforcement_dependency_unavailable`), delays nobody else, and schedules a full
recompute 5 s later, so the peer returns within seconds once the read works again. Only the write takes the
`edge_state` row lock, and a peer is written only if no fresher ticket was applied (`appliedSeq`),
so a slow, stale read never overwrites a newer one. Large refreshes run in batches of 200 peers,
one short write transaction each. A peer is `cut` while any of
these holds, else `active` (the first one found is the `cutReason`):

| Stop condition                                                    | `cutReason`                                |
| ----------------------------------------------------------------- | ------------------------------------------ |
| Platform kill switch                                              | `platform_kill_switch_active`              |
| Tenant not ACTIVE (platform suspension, deletion)                 | `tenant_suspended`, `tenant_deleted`, ...  |
| Agent not ACTIVE (revoked, killed, pending)                       | `agent_status_revoked`, ...                |
| Tenant kill switch (the humans' or the platform's suspension row) | `tenant_kill_switch_active`                |
| Agent kill switch                                                 | `agent_kill_switch_active`                 |
| Agent quarantined                                                 | `agent_quarantined`                        |
| Agent group kill switch                                           | `agent_group_kill_switch_active`           |
| Owning AI system suspended or retired                             | `ai_system_suspended`, `ai_system_retired` |
| No unrevoked certificate                                          | `certificate_revoked`                      |
| Newest unrevoked certificate expired                              | `certificate_expired`                      |
| A lookup failed (fail closed)                                     | `enforcement_dependency_unavailable`       |

The agent-level checks are `KillSwitchService.checkAgent`, the same function the decision path uses
for ancestors, so a stop condition added there also cuts the network path.

Every code path that changes one of these refreshes the affected peers right after its own commit
and before it answers:

| Change                                           | Where                                   | Peers refreshed                            |
| ------------------------------------------------ | --------------------------------------- | ------------------------------------------ |
| Quarantine, release (and its rollback)           | `AgentQuarantineService`                | the agent                                  |
| Agent / group / tenant kill switch on and off    | `KillSwitchService.activate/deactivate` | the agent, the group's members, the tenant |
| Platform kill switch on                          | `PlatformKillSwitchService.activate`    | all                                        |
| Platform kill switch release (two-person flow)   | `PlatformOpsController.release`         | all                                        |
| Tenant suspend, resume, delete                   | `PlatformService`                       | the tenant                                 |
| Agent revoked (certificates revoked with it)     | `AgentsService.revokeAgent`             | the agent                                  |
| Agent enrolled (status ACTIVE)                   | `AgentsService.enroll`                  | the agent                                  |
| AI system state change; agent linked or unlinked | `AiSystemsService`                      | the system's agents; the agent             |
| Egress rule added or removed                     | `EgressRulesController`                 | the agent                                  |

The hooks never fail the action they follow. A failed refresh is retried twice (100 ms, 300 ms); if
it still fails, a full recompute runs 5 s later on that replica. The reconcile recomputes every peer
at boot and then every 60 s on the replica holding the lease, which also covers changes made to a
tenant database outside these paths. A timer, armed at boot and re-armed after every refresh and
every time it fires, runs at the earliest certificate expiry among active peers, so an expired certificate cuts its peer at expiry without any other change. Back to `active` happens only when a recompute finds nothing that stops the
agent, and every way back (release, deactivation, resume, AI system back to ACTIVE) is a human API
call.

`edge_state.version` is global and monotonic. Every change to any peer bumps it once per
transaction, holding the row lock until commit, so versions commit in order; each peer row keeps the
version of its last change.

## Gateway sync API

On the HTTP port only. `EdgeHttpModule` is imported by `AppModule` and never by
`AgentMtlsAppModule`, so `/internal/*` does not exist on the agent mTLS listener
(`test/edge.e2e-spec.ts` checks it with a valid agent certificate). Both routes need
`Authorization: Bearer <MANAR_EDGE_GATEWAY_TOKEN>`, compared in constant time; anything else is a
bare 401. They are left out of the OpenAPI document.

The controls are the token and the NetworkPolicy (only the gateway pods reach the HTTP port from
outside manar-prod). Public ingress must never route `/internal/*` (manar-infra adds an explicit
deny). As defence in depth only, the routes answer 404 to any request carrying a header an ingress,
proxy or CDN adds and the gateway, calling the pod directly, never sends: `X-Forwarded-For`,
`X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Forwarded`, `X-Real-IP`, `Via`,
`CF-Connecting-IP`, `True-Client-IP`.

- `GET /internal/v1/edge/peers?after=<version>`: `after=0`, a missing value or a version the server
  does not have (higher than its own) returns `full: true` with every peer, cut ones included.
  Otherwise the peers changed since `after`, at once if any, else after waiting up to 25 s (then
  200 with the same version and no peers). History is never pruned, so a lower version is always
  answered with a delta. Waiting holds no database connection: a waiter is woken by its own
  instance's commits, by Postgres `NOTIFY manar_edge_peers` (one `LISTEN` connection per API
  instance, opened on the first poll and reopened a second after it drops, so a change on any
  replica wakes waiters on every replica), and re-reads the version every 5 s in case a
  notification is lost.
- `POST /internal/v1/edge/events`: `{ events: [...] }`, at most 500 (400 above). Each valid record
  becomes an `agent.egress.allowed` or `agent.egress.denied` audit event in the peer's tenant, actor
  the agent, data: peer id, time, host (lowercased; hostnames or address literals only, never paths
  or payloads), port, reason, byte counts, duration and `ech` (optional boolean: the ClientHello
  carried encrypted_client_hello; `null` when the gateway did not say). `reason` is an open set
  matching `^[a-z_]{1,40}$` (`allowed`, `host_not_allowed`, `port_not_allowed`, `sni_mismatch`,
  `ech_not_allowed`, `private_address`, `peer_cut`, `dns_failed`, `dial_failed`, ...). Records
  with an unknown peer or an invalid shape are skipped; so are a tenant's records when writing them
  fails (database gone, suspended, unavailable), without failing the other tenants. The answer is
  `{ accepted, skipped, duplicates }`, one transaction per tenant. Optional `batchId`, a
  UUID (400 otherwise; the gateway sends a v4 per batch, a contract addition): each tenant claims
  it in its own `edge_event_batches` table inside the same transaction as the audit events (rows
  kept a day), so a retried batch is recorded once (`duplicates`) and a crash between claim and
  write cannot happen.

## Egress allow-list

Tenant database `agent_egress_rules`. `GET/POST /agents/:id/egress-rules` and
`DELETE /agents/:id/egress-rules/:ruleId`, JWT plus `SECURITY_ADMIN` or `TENANT_OWNER` (the same gate
as the rest of `/agents`). Agents cannot call them (they exist only on the HTTP app) and no AI tool
writes them. `host` is lowercased and must be a DNS name or `*.` plus a DNS name of two labels or
more, under a top-level domain the ICANN section of the Public Suffix List delegates (so internal
names such as `.svc`, `.lan`, `.corp`, `.home`, `cluster.local` never pass); IPs, ports, paths and
other wildcards are refused (400), as are special-use names (`.local`,
`.internal`, `.localhost`, `.onion`, `.arpa`, `.test`, `.invalid`, `.alt`) and a wildcard over a
public suffix (`*.co.uk`, `*.github.io`). The suffixes come from a vendored, dated snapshot of the
Public Suffix List (`src/edge/public-suffix-list.ts`, MPL-2.0; no runtime dependency, refresh by
regenerating it). A duplicate is 409, at most 200 rules per agent. Each change commits together with its `agent.egress_rule.added` / `.removed` audit event,
then the peer's `allowHosts` is recomputed and the version bumped.

## Edge status for the console

`GET /agents/:id/edge`, same gate as the allow-list (JWT plus `SECURITY_ADMIN` or `TENANT_OWNER`,
HTTP app only). The agent is looked up in the caller's tenant database first (404 if it is not
there, so another tenant's agent is never found), then its `edge_peers` row by tenant and agent.
The answer is what the last refresh wrote, never recomputed on read:

```json
{
  "enrolled": true,
  "state": "cut",
  "cutReasons": ["agent_quarantined"],
  "address": "100.88.0.17/32",
  "updatedAt": "2026-10-26T10:00:00.000Z"
}
```

`{ "enrolled": false }` when the agent has no peer. `cutReasons` is present only when `state` is
`cut` and holds the row's `cutReason` (the first stop condition found, so one entry today). No
public key, slugs or allow-list: the allow-list has its own route.

## Claude Code on a governed host

The host binary's Claude Code hook asks Manar before every tool call: `POST /agent/v1/authorize`
with `toolId: "host.claude-code"`, `actionId` = the Claude Code tool name lowercased, and the
command, file path or URL as `resource`. Manar decides it like any other action (kill switches,
task grant in OpenFGA, policy, risk, approval). Manar never runs these actions: the tool row is
registered with `enabled: false`, so `/agent/v1/tools/invoke` refuses them and the MCP manifest does
not list them; authorization does not read `enabled`.

`APPROVAL_REQUIRED` from `/agent/v1/authorize` opens an approval request (and its workflow) the same
way `tools/invoke` does, and the response carries `approvalId` and `expiresAt`. The hook polls
`GET /agent/v1/approvals/{approvalId}` with the same agent certificate (another agent gets 404) and
treats `APPROVED` as allow: a local action redeems no grant, because Manar executes nothing; the
grant the approval issues simply expires. `DENIED`, `EXPIRED` or no answer within its wait is a deny.
If the approval cannot be opened (Temporal down), the verdict comes back without `approvalId` and
the hook denies.

Registered actions (`src/tools/host-actions.ts`) and their risk with the default task ceiling of 20
(score = baseline 10 + base + 15 mutating + 25 destructive):

| Action                                                    | Base | Mutating | Destructive | Score | Default outcome |
| --------------------------------------------------------- | ---- | -------- | ----------- | ----- | --------------- |
| `read`, `glob`, `grep`, `ls`, `notebookread`, `todowrite` | 0    | no       | no          | 10    | runs            |
| `task`, `websearch`                                       | 5    | no       | no          | 15    | runs            |
| `webfetch`                                                | 10   | no       | no          | 20    | runs            |
| `edit`, `multiedit`, `write`, `notebookedit`              | 10   | yes      | no          | 35    | approval        |
| `bash`                                                    | 20   | yes      | yes         | 70    | approval        |

Any other tool name is still decided (an action the task does not grant is denied) but adds no risk
of its own.

Setting up an agent, as a tenant admin:

1. Create the agent and an enrollment token (`POST /agents`, `POST /agents/:id/enrollment-tokens`,
   or the console).
2. On the host, as root: `manar-edge enroll --api https://<manar> --token <token>`, then
   `manar-edge install-claude-code <agent>` (managed settings with the hook, `ANTHROPIC_BASE_URL`
   pointing at the local gateway).
3. Allow the hosts the agent needs beyond Manar (`POST /agents/:id/egress-rules`), if any.
4. Create a task for the agent with the actions it may use, for example
   `allowedToolActions: [{ toolId: "host.claude-code", actionId: "read" }, { ..., actionId: "edit" },
{ ..., actionId: "bash" }]`, `allowedResourceSelectors: [{ toolId: "host.claude-code", pattern:
"*" }]` (or exact resources), and a `riskCeiling` that decides what runs without a person (20:
   reads run, edits and shell commands wait for approval). Use `forbiddenActions` for what must never
   run.
5. Start the session with that task: `manar-edge up <agent> --task <taskId>` and
   `manar-edge run <agent> --task <taskId> -- claude`.
6. Approve or deny waiting actions in the console (or `POST /approvals/:id/decide`); the hook waits
   up to 10 minutes and denies on anything but an approval.

## Not done here

- The gateway itself, the host binary and the console panel are other repos.
- Last handshake time: the gateway does not report it yet, so the status has none.
- `edge_peers` lives in the control database although it names agents: the gateway serves every
  tenant and needs one registry. It holds slugs, keys, addresses and allowed hostnames only.
