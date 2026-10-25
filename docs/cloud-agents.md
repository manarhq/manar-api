# Cloud agents: public MCP with OAuth

Agents that run in a vendor's cloud (Microsoft Copilot Studio, OpenAI ChatGPT) cannot hold a Manar
client certificate. They reach their tools through a public MCP endpoint on the HTTP app, with an
OAuth access token from the tenant's Keycloak realm. From the token on, every call takes the same
path as the mTLS MCP server (`docs/mcp.md`, ADR-0002): kill switches, quarantine, task liveness,
OpenFGA, policy, risk, approvals, DLP, the credential broker and the audit chain. Contract:
`manar-edge/docs/design.md` section 7.

Code: `src/cloud-mcp/` (guard, body limit, controller, admin API), Keycloak calls in
`src/keycloak/keycloak-admin.client.ts`, schema in `prisma/tenant.prisma` (`AgentKind`,
`CloudAgentBinding`). Tests: `src/cloud-mcp/*.spec.ts`, `test/cloud-mcp.e2e-spec.ts` (real
Keycloak, authorization code flow with PKCE, an upstream realm standing in for Entra ID).

## URLs

| What                                                         | URL                                                                                          |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| MCP endpoint (Streamable HTTP, `POST` only, stateless JSON)  | `https://<MANAR_MCP_HOST>/mcp/<tenantSlug>/<agentSlug>`                                      |
| Protected resource metadata (RFC 9728)                       | `https://<MANAR_MCP_HOST>/.well-known/oauth-protected-resource/mcp/<tenantSlug>/<agentSlug>` |
| Authorization server (the tenant realm, `iss` of its tokens) | `<Tenant.keycloakIssuerUrl>`, e.g. `https://id.example.com/realms/<tenantSlug>`              |

The MCP URL is per agent, not one `/mcp` per install. A client learns which authorization server
to use from the protected resource metadata before it has a token, so the URL must name the tenant;
it names the agent too so that the token audience binds the token to one agent. The tenant still
comes from the token: a path whose tenant does not match the verified issuer is refused (401).

## What Keycloak holds per cloud agent

| Object                                | Purpose                                                                                                                                                                                                                             |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| realm role `manar-agent-<slug>`       | Who may use the agent. The tenant admin assigns it (or names an Entra group, below).                                                                                                                                                |
| client scope `manar-mcp-<slug>`       | Audience mapper (the MCP URL) and a role mapper writing the agent role into `manar_roles`. Its only scope mapping is the agent role, so Keycloak applies it only to people holding the role. Not a realm default or optional scope. |
| client `manar-cloud-<slug>` (Copilot) | Confidential, authorization code with PKCE S256, the scope as a default scope, no password grant, no implicit flow, no service account, no full scope.                                                                              |
| DCR policy entry (ChatGPT)            | The scope is listed in the realm's anonymous "Allowed Client Scopes" policy, and the anonymous "Trusted Hosts" policy requires every redirect URI on `MANAR_MCP_DCR_TRUSTED_HOSTS` (default `chatgpt.com`).                         |
| Entra mapper (optional)               | `groups` claim containing the named Entra group id gives the agent role at sign-in.                                                                                                                                                 |

Keycloak ignores the RFC 8707 `resource` parameter unless started with the experimental
`resource-indicators` feature; the client scope is how the audience gets into the token.

## What a token must be

`CloudMcpAuthGuard`, in this order (first failure wins). The body limit runs before it.

| Check                                                                                                    | Failure                                                                             |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `MANAR_MCP_ENABLED` and a slug pair in the path                                                          | 404                                                                                 |
| a POST declares `Content-Length` (no chunked body) at most `MANAR_MCP_MAX_BODY_BYTES`, before it is read | 411, 413                                                                            |
| at most 600 requests a minute from one address to one tenant, before any token work                      | 429 + `Retry-After`                                                                 |
| `Authorization: Bearer` present                                                                          | 401 + `WWW-Authenticate: Bearer resource_metadata="...", scope="manar-mcp-<agent>"` |
| `iss` is an ACTIVE tenant's provisioned realm, and that tenant is the one in the path                    | 401 `unknown_issuer`, `issuer_tenant_mismatch`                                      |
| signature (realm JWKS, cached by `jose`), RS256/384/512 only                                             | 401 `invalid_token`                                                                 |
| not expired (no clock skew); `aud` contains this agent's exact MCP URL and no other agent's              | 401 `token_expired`, `wrong_audience`, `foreign_audience`                           |
| `typ` is `Bearer` (an access token)                                                                      | 401 `not_an_access_token`                                                           |
| the agent exists, is kind `CLOUD` with a binding, and is `ACTIVE`                                        | 403 `unknown_agent`, `agent_not_active`                                             |
| `manar_roles` holds `manar-agent-<slug>`                                                                 | 403 `user_not_allowed`                                                              |
| `scope` holds `manar-mcp-<slug>` and `azp` is the agent's client (see ChatGPT below for the first use)   | 403 `unknown_client` + `WWW-Authenticate: ... error="insufficient_scope"`           |
| per-agent limit `MANAR_MCP_RATE_LIMIT_PER_MINUTE`                                                        | 429 + `Retry-After`                                                                 |
| realm JWKS, control DB, tenant DB, Keycloak admin API (first ChatGPT use) or limits store unreachable    | 503 `enforcement_dependency_unavailable`                                            |

Every refusal counts in `manar_cloud_mcp_token_rejections_total{reason}`. Refusals before the
signature verified never touch a tenant database: they are logged once a minute per address and
tenant at most. Refusals after it are written to the issuer tenant's audit chain as
`cloud_mcp.token_rejected`: reason, agent slug, the client id and the first 16 hex of the token's
SHA-256, never the token.

Then `AgentRuntimeController.serveMcp` runs the governed MCP server for the agent and its standing
task. A quarantined agent, any kill switch (platform, tenant, group, agent, AI system) or a lapsed
task comes back as a tool result with `status: DENIED` and the reason, exactly as on the mTLS
listener.

The public endpoint is not counted in the human API's per-tenant rate limit; it has its own
per-address and per-agent limits.

## Operator set-up (once per install)

1. Set `MANAR_MCP_ENABLED=true` and `MANAR_MCP_HOST=mcp.<domain>` (chart `config`, off by default).
   `MANAR_MCP_DCR_TRUSTED_HOSTS` takes plain host names only.
2. Route `https://mcp.<domain>` to manar-api's HTTP port for the paths `/mcp/` and
   `/.well-known/oauth-protected-resource/` only (manar-infra ingress and the tunnel).
3. Keycloak must be reachable by the vendors at the realm issuer URL, and that URL must be the `iss`
   of its tokens (`Tenant.keycloakIssuerUrl`). Expose Keycloak's root `/.well-known/` path too:
   MCP clients look for `https://<keycloak>/.well-known/oauth-authorization-server/realms/<realm>`
   first.

## Tenant admin: broker the tenant's Entra ID (once per tenant)

1. In Entra ID, register a single-tenant app (web platform), create a client secret, and add the
   `groups` claim (security groups, as group ids) to its ID token if Entra groups will grant agent
   roles.
2. As TENANT_OWNER:

   ```
   PUT /cloud-agents/entra-identity-provider
   { "directoryId": "<Entra tenant id>", "clientId": "<app id>", "clientSecret": "<secret>" }
   ```

   This creates or updates the realm's `entra` OIDC provider (issuer
   `https://login.microsoftonline.com/<directoryId>/v2.0`, PKCE, signature validation). Emails from
   Entra are not trusted, and its first login uses the flow `manar first broker login`, which only
   creates a new user: an Entra identity whose email or username matches an existing account is
   refused, never linked to it, so no one can sign in as an existing account (a tenant owner, for
   example) by giving their Entra account that email. Brokered users are keyed on the token `sub`
   (stable per user for the app registration). The secret goes to Keycloak only. The response
   holds `redirectUri` (`<issuer>/broker/entra/endpoint`).

3. Add that `redirectUri` to the Entra app registration's web redirect URIs.
4. Optional, in the Keycloak admin console: Authentication, `browser` flow, Identity Provider
   Redirector, Default Identity Provider `entra`. Keep a break-glass local admin.

Audit: `tenant.identity_provider_configured` (directory and app ids, never the secret).

## Who may use an agent

Only people holding the realm role `manar-agent-<slug>` (in the connect response as `role`). Give
it either:

- by naming an Entra group when connecting (`"entraGroupId": "<group object id>"`; needs the Entra
  provider first): members get the role at every sign-in; or
- in the Keycloak admin console (Users or Groups, Role mapping), for people already in the realm.

## Connect a Copilot Studio agent

1. As SECURITY_ADMIN or TENANT_OWNER:

   ```
   POST /cloud-agents
   {
     "slug": "helpdesk-copilot", "displayName": "Helpdesk Copilot", "platform": "COPILOT_STUDIO",
     "entraGroupId": "<optional Entra group id>",
     "task": { "name": "Helpdesk standing task",
               "allowedToolActions": [ ... ], "allowedResourceSelectors": [ ... ],
               "expiresAt": "2027-01-01T00:00:00Z", "riskCeiling": 40 }
   }
   ```

   `task` takes the same fields as `POST /tasks`. The response has `mcpUrl`, `authorizationUrl`,
   `tokenUrl`, `refreshUrl`, `scopes`, `role`, `clientId` and `clientSecret`. **The secret is shown
   only in this response.** 409 when the slug is taken or the realm already has a client, scope or
   role of that name. If the call fails part way, everything it made is undone; call it again with
   the same slug.

2. In Copilot Studio: the agent, Tools, Add a tool, New tool, Model Context Protocol. Server URL =
   `mcpUrl`. Authentication: OAuth 2.0, type **Manual**. Paste client id, client secret,
   authorization URL, token URL template (`tokenUrl`), refresh URL (`refreshUrl`) and scope
   (`scopes[0]`). Create.
3. Copilot Studio shows a callback URL. Register it:
   `PUT /cloud-agents/<agentId>/redirect-uris { "redirectUris": ["<callback URL>"] }`.
4. Create the connection in Copilot Studio and sign in as a person holding the agent role.

## Connect a ChatGPT agent

1. `POST /cloud-agents` as above with `"platform": "CHATGPT"`. The response has `mcpUrl`,
   `registrationUrl`, `scopes` and `role`; there is no client id or secret.
2. In ChatGPT (workspace admin): add a custom connector (MCP), server URL = `mcpUrl`,
   authentication OAuth. ChatGPT reads the metadata, registers a client (its registration may ask
   only for `manar-mcp-<slug>`; Keycloak refuses names it does not allow, `openid` included) and
   sends the person to sign in and consent.
3. The first client that presents a fully valid token for the agent (right audience, scope and a
   person with the role) is recorded for it, after Manar checks in Keycloak that every redirect URI
   is on a DCR trusted host and turns off that client's password grant, implicit flow and service
   account. Any other client is refused (`unknown_client`). If the connector is recreated in
   ChatGPT, `DELETE /cloud-agents/<agentId>/oauth-client` deletes the recorded client so the next
   one is recorded.

## Approvals

An action that needs a person's approval returns, as on the mTLS listener:

```json
{ "status": "PENDING", "approvalId": "...", "reason": "...", "nextStep": "..." }
```

Nothing has run. A cloud agent cannot be woken up later, so it either calls
`manar_approval_status` with the `approvalId` (waits up to 50 seconds, default 25, repeatable), or
tells the person to approve in the Manar console and to ask again: calling the same tool with
exactly the same arguments after approval runs it once (ADR-0007). A repeated call while still
pending returns the same open approval. Vendor tool-call timeouts are shorter than an approval
usually takes, so the second path is the normal one.

## Life cycle

- **Standing task expired or revoked**: every call is DENIED. Create a new task with `POST /tasks`
  (`assignedAgentId` = the agent) and bind it: `PUT /cloud-agents/<agentId>/task { "taskId" }`.
- **Stop the agent now**: kill switches and quarantine apply on the next call.
- **Disconnect**: `DELETE /cloud-agents/<agentId> { "reason": "..." }` revokes the agent and its
  standing task (403 `agent_not_active` from the next call), then removes its client, scope, role,
  Entra mapper and DCR policy entry; when no ChatGPT agent is left in the tenant the trusted hosts
  are removed and anonymous registration is closed again. Repeat the call if Keycloak fails part
  way. Cloud agents have no certificate: `POST /agents/:id/enrollment-tokens` and
  `POST /agents/:id/revoke` answer 409 for them.
- **Audit**: `cloud_agent.connected`, `cloud_agent.updated`, `cloud_agent.disconnected`,
  `cloud_mcp.token_rejected`, and every decision with `channel: MCP` for the agent.

## Known gaps

- Not verified against the real vendors: Copilot Studio and ChatGPT were not connected, and Entra
  ID was replaced by a Keycloak realm in the tests.
- The recorded ChatGPT client is whichever self-registered client first presents a valid token of
  a person holding the role; a person with the role could record a client of their own first.
  `DELETE /cloud-agents/<agentId>/oauth-client` resets it.
- A ChatGPT registration that asks for `openid` or other scopes is refused by Keycloak's policy;
  whether ChatGPT asks only for the scopes in the metadata is not verified.
