# ADR-0010: platform API and signed heartbeat for manar-fleet

- Status: proposed (8 Oct 2026, manar-api MR on `feat/fleet-platform-api`)
- Context owner: H3 (manar-fleet); reviewer: Mohamed

## Context

manar-fleet (internal staff service, `docs/hq/HQ-PLAN.md`) keeps the registry of customers,
tenants and deployments, runs upgrades and invoices. It must create, suspend, resume and delete
tenants in a deployment, show per-tenant admins, tools, agent counts and usage, and see each
deployment's version, health and backup status. manar-api had no service-level API for any of
this: tenants were created only by `pnpm manar tenant:create`, with no suspend or resume at all.
manar-api stays the security control plane, so the addition has to be small and fail closed.

## Decision

1. **Platform API** `/platform/v1/tenants` (list, create, summary, suspend, resume, delete), in
   the human HTTP app only, never on the agent mTLS listener.
   - Auth: an access token from `PLATFORM_API_ISSUER` (the platform realm, `master` today),
     verified against that realm's JWKS, `typ` Bearer, `azp` equal to `PLATFORM_API_CLIENT_ID`
     (a confidential client-credentials client, default `manar-fleet`), and the realm role
     `PLATFORM_API_ROLE` (default `manar-platform-admin`) on its service account.
   - Fails closed: unset issuer, every route 503; JWKS unreachable, 503
     `enforcement_dependency_unavailable`; any other check, 401 or 403. Tenant realm tokens never
     pass (different issuer), and this token is never accepted on tenant routes (its issuer is
     not a tenant).
   - Suspend, in this order: (1) the platform's own TENANT-scope kill switch row in the tenant
     database (fixed id `platform-suspension`, `targetId` `platform:manar-fleet`), written with
     one `INSERT ... ON CONFLICT` statement, its `kill_switch.activated` audit event in the same
     transaction (no event, no switch). `KillSwitchService.checkAll` denies on any active TENANT
     row, and every process (API replicas, the Temporal worker) reads kill switches per decision,
     so agent requests and grant redemption are denied at once everywhere; (2) the control status
     SUSPENDED, which refuses humans at once (`KnownIssuerRegistry` and `AgentMtlsGuard` read it
     per request) and evicts the caller's cached tenant client. Delete sets the same switch, then
     DELETED.
   - The humans' tenant switch (`targetId` null, the console's) is a separate row the platform
     never reads or writes. Resume flips the status back, then turns off only the platform row
     with one conditional `UPDATE ... WHERE id = 'platform-suspension' AND active`, audited in the
     same transaction. A human stop pressed before, during or after a suspension survives resume.
   - Cached tenant clients in other processes: `getClient` re-reads the tenant's status when a
     cached entry is older than `TENANT_DB_CLIENT_REVALIDATE_MS` (default 5 s), refuses a tenant
     that is no longer ACTIVE, fails closed if the control DB is unreadable, and on a cache miss
     re-checks the status after connecting, before caching (the window starts at the read).
   - Residual window: work already past its kill-switch check when the switch lands (one
     in-flight request or activity) completes; anything that does not pass through the decision
     path keeps a cached client for at most the revalidation TTL. Upgrade path: pub/sub eviction.
   - The summary returns admin contacts (TENANT_OWNER and SECURITY_ADMIN display name and email),
     tool names, agent counts and 30-day counts of tasks, tool invocations and approval requests:
     no tenant business data.
2. **Signed heartbeat** (off by default). With `FLEET_HEARTBEAT_URL` and `FLEET_DEPLOYMENT_ID`
   set, the API posts every `FLEET_HEARTBEAT_INTERVAL_MINUTES` an envelope
   `{payload: base64(JSON), signature: base64(Ed25519)}`. Payload: version, git sha, readiness of
   each dependency, backup status (from `FLEET_BACKUP_STATUS_FILE`, written by the backup job),
   and counts (tenants, active tenants, agents, active agents), with a timestamp and a random
   nonce. manar-fleet verifies the signature against the registered public key, rejects any
   field outside its schema, and rejects replays by monotonic timestamp and nonce. The private key
   lives in OpenBao KV (`FLEET_HEARTBEAT_KEY_PATH`); `pnpm manar fleet:keygen` creates it and
   prints only the public key. Installs without outbound access run `pnpm manar fleet:report
--out report.json` and upload the file in the admin console (same verification).
3. **Deploy jobs** in `deploy/ci/fleet-deploy.gitlab-ci.yml`, started by manar-fleet through the
   pipeline trigger API with `FLEET_MODE` dry-run (helm diff between marker lines), apply (helm
   upgrade --atomic) or rollback (helm rollback). All other jobs are skipped in those pipelines.
   Every FLEET_* input is validated as a whole value (`deploy/ci/validate-fleet-inputs.sh`, with
   a shell test in the lint stage) and manar-fleet applies the same rules before triggering; the
   tag goes through `--set-string`. The trigger token is held only by manar-fleet. Kubeconfig per
   deployment is a protected, environment-scoped CI file variable.

## Alternatives considered

- Shared secret header (like `PlatformOperatorGuard`): simpler, but a long-lived static secret
  for create and delete is a wider blast radius than a short-lived, role-scoped OIDC token.
- mTLS between manar-fleet and manar-api: stronger channel binding; deferred, can be added in
  front of the same guard.
- Pull model (manar-fleet polls manar-api): needs inbound access into every customer install;
  the signed push or uploaded report works in both cases.

## Consequences and follow-ups

- Platform actions are logged by manar-api (tenant id and caller client id) and recorded in
  manar-fleet's staff audit log; they are not yet written to the tenant's own audit chain.
- Database migrations are not part of the deploy jobs yet: add a Helm pre-upgrade hook Job that
  runs `prisma migrate deploy` and `pnpm manar tenants:migrate`.
- `HELM_DIFF_VERSION` must be verified against the runner image before the first dry run.
- Setting up the platform client in Keycloak (per deployment):
  `kcadm.sh create clients -r master -s clientId=manar-fleet -s serviceAccountsEnabled=true
-s standardFlowEnabled=false -s publicClient=false`, create realm role `manar-platform-admin`,
  add it to the client's service account, then put the client secret in manar-fleet's env var
  named by that deployment's `platformSecretEnv`. The secret is never committed or printed.

## Addendum (9 Oct 2026): ops routes and heartbeat sections for admin v2

- **Platform kill switch** for manar-fleet: `GET /platform/v1/kill-switch`,
  `POST .../kill-switch/engage` `{reason, staff}`, `POST .../kill-switch/release`
  `{staff, proposedBy?, expectedEngagementId}`. Same control-DB row as
  `POST /kill-switches/platform`. Each engagement is named by its activation time
  (`engagementId`); a release ends only the engagement it names, with one conditional update
  (`WHERE active AND activatedAt = expected`), else 409 `engagement_changed`. So a release
  proposed in manar-fleet for one incident can never end a later stop. Who may engage (one owner,
  at once) and release (proposed, then approved by someone else) is enforced in manar-fleet.
  Residual: the older `POST /kill-switches/platform/deactivate` (tenant admin plus the operator
  token) can still turn it off without a second person.
- **Tenant ops view** `GET /platform/v1/tenants/:id/ops` (ACTIVE tenants): active kill switches
  with who and when (`platform: true` for the suspension row), quarantines active or released in
  the last 30 days with the detector's reason code (the watcher's generated explanation is left
  out), decisions per UTC month for 6 months, agents enrolled, and each tool's credential expiry.
  The expiry is the `expires_at` an operator records in the OpenBao KV metadata, never read from
  the secret: `bao kv metadata put -custom-metadata=expires_at=2026-11-08T00:00:00Z secret/<path>`.
- **Audit chain check** `POST /platform/v1/tenants/:id/audit/verify`: the full chain walk, with
  the event count; the result is kept in manar-fleet.
- **Heartbeat sections** (all optional, strict on both ends; the sender validates with the same
  schema before signing, so nothing outside it is ever sent): `health.openbaoSealed`
  (`/v1/sys/seal-status`), `backup.lastRestoreTestStatus` (from the backup file),
  `expiries[{kind: agent_ca | tls_server | tool_credential, notAfter}]` (no names),
  `auditChain {status, tenantsChecked, tenantsBroken, verifiedAt}` (recomputed at most every
  `FLEET_AUDIT_VERIFY_MINUTES`, default 60), `usage.months[{month, decisions}]` (whole
  deployment) and `killSwitch {active, activatedAt}`. A section that cannot be read is left out.
  Deploy manar-fleet first: it rejects unknown fields.
- **Timed restore drill:** the backup file may carry `lastRestoreTestSeconds`; it rides in
  `backup.lastRestoreTestSeconds`.
- **Per-tenant catalog sections** (catalog workstream, for installs without a platform
  connection): `tenants[{tenantId, catalog {features, packs, model}, llmTokensMonth {month,
tokens}, connectors [{name, type, protocol, enabled, credentialExpiresAt}]}]`. This is the one
  place the heartbeat names tenants (by id) and tools; still config and counts only, built field by
  field so a credential or its reference can never ride along, and strict on both ends. The source
  is bound to `HEARTBEAT_TENANT_CATALOG` (`CatalogService` once the catalog module is on main);
  unbound, the section is left out. A tenant whose section fails is left out and logged by id.
