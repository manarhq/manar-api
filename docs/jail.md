# JAIL site rules (jail track, wave 2)

Per device and tool: which sites an AI tool may reach (ask on new sites). The filter itself runs on the device
(manar-edge `docs/jail.md`).

## Device routes (mTLS, `HostAuthGuard`)

- `POST /host/v1/jail/ask` `{ toolId, site }` -> `{ decision: "allow" | "deny" }` from a remembered rule (a
  DENY, exact or `*.suffix`, always wins and never opens a prompt), or `{ decision: "ask", id, expiresAt }`
  after opening a `HostApproval` (tool = `toolId`, action `site.connect`, resource = the site, not high risk).
  The device polls `GET /host/v1/approvals/:id`.
- `GET /host/v1/config` has a `jail` key: `{ enabled, windows, tools: [toolId], rules: [{ toolId, site, mode,
expiresAt }] }`. `tools` are the device's tools in `host.claude-code`, `host.codex-cli`, `host.gemini-cli`,
  `host.copilot-cli` whose Protect switch is on.
- `POST /host/v1/approvals/:id/decide`: a device may answer `approve_once` or `deny` only.

## Console routes (`JwtAuthGuard`, roles)

- `GET /jail/site-rules?hostId=` (auditor, security admin, owner), `POST /jail/site-rules` and
  `DELETE /jail/site-rules/:id` (security admin, owner). `site` is a name, an IP, or `*.suffix` for a public
  name (never a public suffix like `*.co.uk`).
- `POST /host-approvals/:id/decide` accepts `approve_always` for a `site.connect` approval.

## Decision rules for a `site.connect` approval

- `approve_8h` makes an ALLOW site rule for 8 hours; `approve_always` makes it permanent.
- An approval never overwrites a DENY rule (exact or wildcard) or a rule made by hand in the console; the answer
  then applies once only and the response says `note: "site_rule_exists"`.
- `approve_always` needs the role that can write site rules (owner or security admin). An approver without
  it gets `approve_once` and `note: "always_needs_owner"`.
- A device can never send `approve_8h` or `approve_always`.
- No 8-hour action grant is created for a site prompt; the site rule is the grant.

## Config

`MANAR_JAIL_ENABLED` (default `true`), `MANAR_JAIL_WINDOWS` (default `false`). No secrets.

## Audit

`jail.site_rule.created` (answer to a prompt or by hand), `jail.site_rule.removed`. The prompt itself is audited as
`approval.requested` / `approval.approved` / `approval.denied`.

## Data

Tenant table `host_site_rules` (migration `20261101120400_host_site_rules`, additive; rollback `DROP TABLE`).
