# Phase 14: Users/Roles/Settings & Two Security Cleanups — Design

Status: Approved (autonomous execution)
Scope: `manar-api` (Part 1 — user/role/tenant-settings endpoints, plus
two small security cleanups) and `manar-web` (Part 2 — the
corresponding pages). Part 1 must land before Part 2 starts (same
dependency shape as every prior UI phase).
Depends on: Phase 3 (`UserProfile`/`RoleBinding`), Phase 2 (`Tenant`
residency fields), Phase 11a/11b (auth flow, generated client, design
system)

## Purpose

The remaining Section 60 pages that have real backing data already sitting
in the database but no endpoint exposing it (`/users`, `/roles`), plus
the tenant-settings pages (`/settings/security`, `/settings/sso`,
`/settings/residency`, `/settings/ai`) backed by fields that have existed
since Phase 2 but were never surfaced. Also closes two small,
concretely-identified gaps from Phase 11b/13's honest self-reporting.

## Part 1 — `manar-api`

### Security cleanup 1: idempotency on approval decisions

Phase 11b Part 2 found that two genuinely concurrent
`POST /approvals/:id/decide` calls both return `201`, even though
Temporal's sequential signal processing ensures only one decision
actually takes effect — a response-accuracy gap, not a double-execution
bug, but worth closing since Section 65 explicitly calls this endpoint
out as needing to be race-safe/idempotent. Apply Phase 12a's existing
`Idempotency-Key` interceptor to this endpoint (it wasn't in the original
list Phase 12a picked), OR — if idempotency-key semantics don't fit this
specific race (two _different_ concurrent requests, not a retried
identical one) — have the endpoint synchronously wait for and return the
Temporal workflow's actual resolved decision state instead of returning
immediately post-signal. Pick whichever is the more correct fix, not
just whichever is easier; explain the choice.

### Security cleanup 2: finish removing manar-web's Keycloak admin credentials

Phase 11b closed the client-secret-fetching workaround but `manar-web`'s
BFF still holds standing `KEYCLOAK_ADMIN_*` credentials for one narrow
remaining purpose: registering its own OIDC redirect URI with each
tenant's realm. Add a `manar-api` mechanism for this instead — either
fold redirect-URI registration into `TenantProvisioningService`'s
existing realm-provisioning step (register a known, fixed
`manar-web` redirect URI at tenant-creation time, since it's not
actually dynamic per-login) or expose a narrow, `BffServiceGuard`-gated
endpoint mirroring Phase 11b's `oidc-client-secret` pattern. Read
`manar-web`'s actual current code to see exactly what it does with these
credentials before deciding — don't guess.

### User/role endpoints (JWT-guarded)

- `GET /users` (paginated, Phase 11b's cursor convention) — `UserProfile`
  - their `RoleBinding`s.
- `GET /users/:id`.
- `POST /users/:id/role-bindings` / `DELETE /users/:id/role-bindings/:role`
  — grant/revoke a role (role-gated to `TENANT_OWNER`/`SECURITY_ADMIN`;
  a user must never be able to grant themselves a more privileged role
  than they already hold — enforce this explicitly, don't just rely on
  the endpoint's own role gate, since a `SECURITY_ADMIN` granting
  `TENANT_OWNER` to themselves would be a privilege-escalation bug worth
  a real test).
- Audit every grant/revoke via `AuditService.recordSafely()`.

### Tenant settings endpoints (JWT-guarded, `TENANT_OWNER`/`SECURITY_ADMIN`)

- `GET /tenant/settings` / `PATCH /tenant/settings` — surfaces and lets
  an authorized admin update the `Tenant` fields that have existed since
  Phase 2 (`residency`, `allowExternalAi`, `allowOutboundTelemetry`,
  `allowCloudStorage`) plus whatever's reasonable to expose for
  `/settings/security` (e.g. rate-limit configuration if it's
  per-tenant-adjustable, session/token policy) and `/settings/sso`
  (read-only display of the realm/issuer info from Phase 11b's
  `oidc-config` endpoint — SSO federation configuration itself lives in
  Keycloak, this page can link out rather than duplicate Keycloak's own
  admin UI). `/settings/ai` should reflect whatever `manar-ai` provider
  is actually configured (research whether there's already a way to ask
  `manar-ai` this, or whether it's `manar-api`-side config only — Phase
  12a's `AI_ADVISORY_PROVIDER` env var suggests the latter).
- Changing `allowExternalAi` to `false` must be immediately effective —
  write a test confirming the very next AI-advisory-eligible request
  respects the new value (Phase 12a's existing enforcement point should
  already pick this up naturally since it reads the live `Tenant` row;
  verify, don't just assume).

## Part 2 — `manar-web`

Real pages using the new endpoints, the established design
system/i18n/RTL conventions from Phase 11a/11b:

1. **`/users`**: list with role badges, per-user role grant/revoke UI
   (respecting the backend's privilege-escalation guard — the UI should
   also not offer to grant a role the current user doesn't themselves
   hold, as a UX nicety on top of the backend enforcement, not instead
   of it).
2. **`/roles`**: a read-oriented page describing the eight roles and
   what they can do (this can be substantially static content describing
   the fixed role set established since Phase 3 — there's no dynamic
   custom-role creation in this product).
3. **`/settings/security`**, **`/settings/sso`**, **`/settings/residency`**,
   **`/settings/ai`**: real forms wired to `GET`/`PATCH /tenant/settings`,
   each showing genuinely current values and genuinely persisting
   changes.

## Testing

- Privilege-escalation guard: a `SECURITY_ADMIN` cannot grant themselves
  `TENANT_OWNER`; a `TENANT_OWNER` can grant any role.
- `allowExternalAi` toggling takes effect immediately for the next
  authorization request (real, not assumed).
- Approval decide race fix: reproduce Phase 11b's original two-concurrent-
  calls scenario and confirm the new behavior (whichever fix was chosen)
  is actually correct now.
- `manar-web`: role grant/revoke UI round-trips against the real API;
  settings forms persist and reflect real backend state on reload.
- Existing e2e suites across all prior phases still pass unmodified, in
  both repos.

## Out of scope this phase

- `/incidents`, `/compliance`, `/integrations` (still lower priority,
  still honest stubs)
- Custom/dynamic role definitions beyond the fixed eight
- SSO federation configuration UI beyond a read-only display + link-out
  to Keycloak's own admin console
