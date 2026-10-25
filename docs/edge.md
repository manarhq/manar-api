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

`POST /agents/enroll` takes an optional `edge: { wgPublicKey }`. The key is checked before the
enrollment token is looked at, so a refused edge request never burns the token:

- edge off: 400 `{ code: "edge_not_enabled" }`;
- not canonical base64 of 32 bytes: 400;
- the key belongs to another agent: 409.

After the certificate is issued, the agent's peer is created, or replaced on re-enrollment (new key,
same peer id and address: one peer per agent), and the response carries the `edge` object of the
contract (`peerId`, `address`, `gatewayPublicKey`, `gatewayEndpoint`, `manarAddress`,
`manarServerName`, `proxyAddress`, `keepaliveSeconds`). The host tool `host.claude-code` is
registered in the tenant at the same time (see below).

Address allocation runs under the global edge lock (the `edge_state` row), takes the lowest address
no `edge_peers` row holds, and a unique index backs it, so two enrollments at once, on any replica,
in any tenant, never get the same address. Rows are not deleted while their tenant exists, so an
address is never reused while a row holds it.

## Peer state

`edge_peers` (control database) is the platform registry the gateway reads. It is a projection: the
tenant database stays the source of truth. `EdgePeerService` recomputes a peer from it, under the
`edge_state` row lock, and writes `state`, `cutReason` and `allowHosts`. A peer is `cut` while any of
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

The hooks never fail the action they follow. If a refresh fails, or something changes the tenant
database without going through these paths, the reconcile (every 60 s, on one replica at a time)
recomputes every peer. Back to `active` happens only when a recompute finds nothing that stops the
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

- `GET /internal/v1/edge/peers?after=<version>`: `after=0`, a missing value or a version the server
  does not have (higher than its own) returns `full: true` with every peer, cut ones included.
  Otherwise the peers changed since `after`, at once if any, else after waiting up to 25 s (then
  200 with the same version and no peers). History is never pruned, so a lower version is always
  answered with a delta. Waiting holds no database connection: a waiter is woken by its own
  instance's commits, by Postgres `NOTIFY manar_edge_peers` (one `LISTEN` connection per API
  instance, opened on the first poll, so a change on any replica wakes waiters on every replica),
  and re-reads the version every 5 s in case a notification is lost.
- `POST /internal/v1/edge/events`: `{ events: [...] }`, at most 500 (400 above). Each valid record
  becomes an `agent.egress.allowed` or `agent.egress.denied` audit event in the peer's tenant, actor
  the agent, data: peer id, time, host (lowercased; hostnames or address literals only, never paths
  or payloads), port, reason, byte counts, duration and `ech` (optional boolean: the ClientHello
  carried encrypted_client_hello; `null` when the gateway did not say). `reason` is an open set
  matching `^[a-z_]{1,40}$` (`allowed`, `host_not_allowed`, `port_not_allowed`, `sni_mismatch`,
  `ech_not_allowed`, `private_address`, `peer_cut`, `dns_failed`, `dial_failed`, ...). Records
  with an unknown peer, an invalid shape, or whose tenant database is gone are skipped; the answer
  is `{ accepted, skipped }`. One transaction per tenant.

## Egress allow-list

Tenant database `agent_egress_rules`. `GET/POST /agents/:id/egress-rules` and
`DELETE /agents/:id/egress-rules/:ruleId`, JWT plus `SECURITY_ADMIN` or `TENANT_OWNER` (the same gate
as the rest of `/agents`). Agents cannot call them (they exist only on the HTTP app) and no AI tool
writes them. `host` is lowercased and must be a DNS name or `*.` plus a DNS name of two labels or
more; IPs, ports, paths and other wildcards are refused (400), a duplicate is 409, at most 200 rules
per agent. Each change commits together with its `agent.egress_rule.added` / `.removed` audit event,
then the peer's `allowHosts` is recomputed and the version bumped.

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
- Expired certificates do not cut a peer (the mTLS listener refuses them anyway); revocation does.
- `edge_peers` lives in the control database although it names agents: the gateway serves every
  tenant and needs one registry. It holds slugs, keys, addresses and allowed hostnames only.
