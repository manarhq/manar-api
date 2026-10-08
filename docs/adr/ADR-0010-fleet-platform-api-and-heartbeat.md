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
   - Suspend sets the tenant SUSPENDED and evicts its cached client. Humans are refused at once
     (`KnownIssuerRegistry` needs ACTIVE), agents too (`AgentMtlsGuard` now checks the tenant
     status), and `getClient` refuses the tenant. Resume reverses it. Delete marks DELETED and keeps
     the database and realm (dropping them stays a manual, separate step).
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
   Kubeconfig per deployment is a protected, environment-scoped CI file variable.

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
