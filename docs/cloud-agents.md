# Cloud agents: public MCP with OAuth

Agents that run in a vendor's cloud (Microsoft Copilot Studio, OpenAI ChatGPT) cannot hold a Manar
client certificate. They reach their tools through a public MCP endpoint on the HTTP app, with an
OAuth access token from the tenant's Keycloak realm. From the token on, every call takes the same
path as the mTLS MCP server (`docs/mcp.md`, ADR-0002): kill switches, quarantine, task liveness,
OpenFGA, policy, risk, approvals, DLP, the credential broker and the audit chain. Contract:
`manar-edge/docs/design.md` section 7.

Code: `src/cloud-mcp/` (guard, controller, admin API), Keycloak calls in
`src/keycloak/keycloak-admin.client.ts`, schema in `prisma/tenant.prisma` (`AgentKind`,
`CloudAgentBinding`). Tests: `src/cloud-mcp/*.spec.ts`, `test/cloud-mcp.e2e-spec.ts` (real
Keycloak).

## URLs

| What                                                         | URL                                                                                          |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| MCP endpoint (Streamable HTTP, `POST` only, stateless JSON)  | `https://<MANAR_MCP_HOST>/mcp/<tenantSlug>/<agentSlug>`                                      |
| Protected resource metadata (RFC 9728)                       | `https://<MANAR_MCP_HOST>/.well-known/oauth-protected-resource/mcp/<tenantSlug>/<agentSlug>` |
| Authorization server (the tenant realm, `iss` of its tokens) | `<Tenant.keycloakIssuerUrl>`, e.g. `https://id.example.com/realms/<tenantSlug>`              |

The MCP URL is per agent, not one `/mcp` per install. A client learns which authorization server
to use from the protected resource metadata before it has a token, so the URL must name the tenant;
it names the agent too so that the token audience binds the token to one agent (a ChatGPT client
registers itself and has no client id Manar could know in advance). The tenant still comes from
the token: a path whose tenant does not match the verified issuer is refused (401).

## What a token must be

`CloudMcpAuthGuard`, in this order (first failure wins):

| Check                                                                                                                                                                          | Failure                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `MANAR_MCP_ENABLED` and a slug pair in the path                                                                                                                                | 404                                                                                                                 |
| `Content-Length` at most `MANAR_MCP_MAX_BODY_BYTES`                                                                                                                            | 413                                                                                                                 |
| `Authorization: Bearer` present                                                                                                                                                | 401 + `WWW-Authenticate: Bearer resource_metadata="...", scope="manar-mcp-<agent>"` (not audited: normal discovery) |
| `iss` is an ACTIVE tenant's provisioned realm                                                                                                                                  | 401 `unknown_issuer`                                                                                                |
| that tenant is the one in the path                                                                                                                                             | 401 `issuer_tenant_mismatch`                                                                                        |
| signature (realm JWKS, cached by `jose`, refetched on an unknown `kid`), RS256/384/512 only, not expired (no clock skew)                                                       | 401 `invalid_token`, `token_expired`                                                                                |
| `aud` contains this agent's exact MCP URL                                                                                                                                      | 401 `wrong_audience`                                                                                                |
| `typ` is `Bearer` (an access token)                                                                                                                                            | 401 `not_an_access_token`                                                                                           |
| the agent exists, is kind `CLOUD` with a binding                                                                                                                               | 403 `unknown_agent`                                                                                                 |
| the agent is `ACTIVE` (not revoked)                                                                                                                                            | 403 `agent_not_active`                                                                                              |
| `azp` is the agent's client (Copilot Studio) or a self-registered client (ChatGPT: not the console client, not a `manar-cloud-*` client); `scope` contains `manar-mcp-<agent>` | 403 `unknown_client` + `WWW-Authenticate: ... error="insufficient_scope"`                                           |
| per-agent limit `MANAR_MCP_RATE_LIMIT_PER_MINUTE` (Redis, local fallback)                                                                                                      | 429 + `Retry-After`                                                                                                 |
| realm JWKS, control DB, tenant DB or limits store unreachable                                                                                                                  | 503 `enforcement_dependency_unavailable`                                                                            |

Every refusal of a presented token writes `cloud_mcp.token_rejected` in the audit chain of the
tenant the path names: reason, agent slug, the unverified client id and the first 16 hex of the
token's SHA-256. Never the token.

Then `AgentRuntimeController.serveMcp` runs the governed MCP server for the agent and its standing
task. A quarantined agent, any kill switch (platform, tenant, group, agent, AI system) or a lapsed
task comes back as a tool result with `status: DENIED` and the reason, exactly as on the mTLS
listener.

## How the audience gets into the token

Keycloak ignores the RFC 8707 `resource` parameter unless started with the experimental
`resource-indicators` feature, so each cloud agent gets a realm client scope `manar-mcp-<agent>`
with an audience mapper (`included.custom.audience` = the MCP URL). The scope is:

- **Copilot Studio**: a default scope of the agent's pre-registered client
  `manar-cloud-<agent>` (confidential, authorization code with PKCE S256, no password grant, no
  service account). Every token of that client carries the audience.
- **ChatGPT**: a realm default optional scope, so a client ChatGPT registers (DCR) is given it and
  may request it. ChatGPT requests the scopes the protected resource metadata lists.

## Operator set-up (once per install)

1. Set `MANAR_MCP_ENABLED=true` and `MANAR_MCP_HOST=mcp.<domain>` (chart `config`, off by default).
2. Route `https://mcp.<domain>` to manar-api's HTTP port for the paths `/mcp/` and
   `/.well-known/oauth-protected-resource/` only (manar-infra ingress and the tunnel). Nothing else
   of the human API belongs on that host.
3. Keycloak must be reachable by the vendors at the realm issuer URL, and that URL must be the `iss`
   of its tokens (`Tenant.keycloakIssuerUrl`). Expose Keycloak's root `/.well-known/` path too:
   MCP clients look for `https://<keycloak>/.well-known/oauth-authorization-server/realms/<realm>`
   first.

## Tenant admin: broker the tenant's Entra ID (once per tenant)

Tenant realms do not broker Entra ID today. To let people sign in with their Entra account when a
vendor connects:

1. In Entra ID, register a single-tenant app (web platform). Create a client secret.
2. Call, as TENANT_OWNER:

   ```
   PUT /cloud-agents/entra-identity-provider
   { "directoryId": "<Entra tenant id>", "clientId": "<app id>", "clientSecret": "<secret>" }
   ```

   This creates or updates the realm's `entra` OIDC identity provider (issuer
   `https://login.microsoftonline.com/<directoryId>/v2.0`, PKCE, signature validation on). The
   secret goes to Keycloak only. The response holds `redirectUri`
   (`<issuer>/broker/entra/endpoint`).

3. Add that `redirectUri` to the Entra app registration's web redirect URIs.
4. Optional, in the Keycloak admin console: Authentication, `browser` flow, Identity Provider
   Redirector, Default Identity Provider `entra`, so sign-in goes straight to Entra. Keep a
   break-glass local admin.

Audit: `tenant.identity_provider_configured` (directory and app ids, never the secret).

## Connect a Copilot Studio agent

1. As SECURITY_ADMIN or TENANT_OWNER:

   ```
   POST /cloud-agents
   {
     "slug": "helpdesk-copilot", "displayName": "Helpdesk Copilot", "platform": "COPILOT_STUDIO",
     "task": { "name": "Helpdesk standing task",
               "allowedToolActions": [ ... ], "allowedResourceSelectors": [ ... ],
               "expiresAt": "2027-01-01T00:00:00Z", "riskCeiling": 40 }
   }
   ```

   `task` takes the same fields as `POST /tasks`; it is created assigned to the new agent. The
   response has `mcpUrl`, `authorizationUrl`, `tokenUrl`, `refreshUrl`, `scopes`, `clientId` and
   `clientSecret`. **The secret is shown only in this response**; Manar does not keep it.

2. In Copilot Studio: the agent, Tools, Add a tool, New tool, Model Context Protocol. Server URL =
   `mcpUrl`. Authentication: OAuth 2.0, type **Manual**. Paste client id, client secret,
   authorization URL, token URL template (`tokenUrl`), refresh URL (`refreshUrl`) and scope
   (`scopes[0]`). Create.
3. Copilot Studio shows a callback URL. Register it:

   ```
   PUT /cloud-agents/<agentId>/redirect-uris
   { "redirectUris": ["<callback URL>"] }
   ```

4. Create the connection in Copilot Studio and sign in (Entra, through the realm). The tools of
   the standing task appear.

Copilot Studio's "Dynamic discovery" (DCR) option is not used for Copilot Studio agents: the
pre-registered client is the supported path.

## Connect a ChatGPT agent

1. `POST /cloud-agents` as above with `"platform": "CHATGPT"`. This opens anonymous dynamic client
   registration in the realm to redirect URIs on `MANAR_MCP_DCR_TRUSTED_HOSTS` only (default
   `chatgpt.com`): the realm's anonymous Trusted Hosts policy accepts a registration from any
   address but requires every redirect URI to be on a trusted host. The response has `mcpUrl`,
   `registrationUrl` and `scopes`; there is no client id or secret.
2. In ChatGPT (workspace admin): add a custom connector (MCP), server URL = `mcpUrl`,
   authentication OAuth. ChatGPT reads the protected resource metadata, the realm's
   authorization server metadata, registers a client and sends the person to sign in. Keycloak's
   default anonymous policies stay on: the new client requires consent, gets no full scope, and
   at most 200 clients may register.
3. Sign in (Entra, through the realm) and approve the consent screen.

The registration may ask only for client scopes of the realm. Keycloak's anonymous "Allowed
Client Scopes" policy refuses a registration whose `scope` names anything else (for example
`openid`, which is not a client scope there). Manar's metadata lists only `manar-mcp-<agent>`.

## Approvals

An action that needs a person's approval returns, as on the mTLS listener:

```json
{ "status": "PENDING", "approvalId": "...", "reason": "...", "nextStep": "..." }
```

Nothing has run. A cloud agent cannot be woken up later, so it either:

- calls `manar_approval_status` with the `approvalId`; that call waits up to 50 seconds (default 25) for the decision and can be repeated while the conversation lasts; or
- tells the person to approve in the Manar console and to ask again; calling the same tool with
  exactly the same arguments after approval runs it once (ADR-0007). A repeated call while still
  pending returns the same open approval, never a second one.

Vendor tool-call timeouts are shorter than an approval usually takes, so the second path is the
normal one.

## Life cycle

- **Standing task expired or revoked**: every call is DENIED. Create a new task with
  `POST /tasks` (`assignedAgentId` = the agent) and bind it:
  `PUT /cloud-agents/<agentId>/task { "taskId": "..." }`.
- **Stop the agent now**: kill switches and quarantine apply on the next call. `POST
/agents/<id>/revoke` makes every token 403 `agent_not_active` (the Keycloak client stays; delete
  it in Keycloak to stop new tokens too).
- **Audit**: `cloud_agent.connected`, `cloud_agent.updated`, `cloud_mcp.token_rejected`, and every
  decision with `channel: MCP` for the agent.

## Limits and known gaps

- Calls also count toward the tenant's human-surface limit (`RATE_LIMIT_HUMAN_LIMIT`), since the
  endpoint is on the HTTP app; raise it if cloud agents are busy.
- Connecting is not one transaction. If Keycloak fails part way, the agent stays
  `PENDING_ENROLLMENT` without a binding and the endpoint refuses it; revoke it and connect again
  with another slug (the realm may keep an unused `manar-mcp-<slug>` scope).
- Any person who can sign in to the realm can use a connected agent through its vendor; the
  agent's authority is its task, the same for every user.
- A DCR client is not tied to one agent: any self-registered client that obtains an agent's scope
  reaches that agent. The Trusted Hosts policy is what limits who can register.
- Not verified against the real vendors: Copilot Studio and ChatGPT were not connected; tokens in
  the e2e suite come from a real Keycloak via the password grant, enabled on the client by the
  test only.
