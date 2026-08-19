# Human authentication

This is `manar-api`'s implementation of Phase 3 (Human Authentication):
`docs/superpowers/specs/2026-08-18-phase3-human-auth-design.md`. It wires
Keycloak as the human identity provider and establishes trustworthy,
tenant-scoped route protection — no SOC UI, no fine-grained authorization
(OpenFGA is Phase 5) — this is the backend auth mechanism only.

## Realm model: one Keycloak realm per tenant

Every tenant gets its own Keycloak realm, its own eight application roles
(seeded as realm roles), and its own confidential `manar-api` client. This
matches the DB-per-tenant isolation philosophy from Phase 2
(`docs/tenant-isolation.md`): a tenant's realm can bring its own SSO/SAML
federation later without touching any other tenant's auth config, and — the
part that matters most for request-time trust — the JWT `iss` (issuer)
claim itself becomes a cryptographically-verified signal of which tenant a
request belongs to, never a client-supplied value.

Realm names equal the tenant's `slug`. The client ID (`manar-api` by
default, `KEYCLOAK_CLIENT_ID`) is the same across every realm — clients are
realm-scoped, so this doesn't collide.

## Provisioning: `TenantProvisioningService`

`src/keycloak/tenant-provisioning.service.ts` wraps Phase 2's
`TenantDatabaseManager.provisionTenant` (unchanged) and adds the Keycloak
leg around it:

1. `TenantDatabaseManager.provisionTenant` — Phase 2 behavior: creates the
   `Tenant`/`TenantDatabaseBinding`/`SecretReference` rows, the tenant's
   isolated Postgres database, and runs its migrations. Ends with the
   tenant `ACTIVE`.
2. `KeycloakAdminClient.createRealm` — creates the realm via the Admin REST
   API, authenticating as the bootstrap master-realm admin
   (`KEYCLOAK_ADMIN_USERNAME`/`KEYCLOAK_ADMIN_PASSWORD`, an infrastructure
   operator per Section 11 — never an application-level super admin, and
   never exposed over Manar's own HTTP surface).
3. Seeds the eight realm roles from `src/auth/roles.ts`'s `ROLES` constant
   — the single source of truth for the role-name convention (see that
   file's doc comment for why the same strings are used identically as
   Keycloak realm roles, `RoleBinding.role` enum values, and
   `@RequireRole(...)` arguments).
4. Creates the confidential `manar-api` client
   (`directAccessGrantsEnabled: true`, so this phase's tests can obtain
   real tokens via the Resource Owner Password Credentials grant without
   fabricating a JWT; `standardFlowEnabled: true` for Phase 11's login
   redirect flow). Since Phase 14 (security cleanup 2), this also seeds
   the client's `redirectUris`/`webOrigins` with `manar-web`'s OIDC
   callback (`<MANAR_WEB_BASE_URL>/api/auth/callback`) and origin — a
   static, deployment-wide value, not something that needs discovering
   per-login — closing the gap that used to require `manar-web`'s BFF to
   hold standing Keycloak admin credentials just to register its own
   callback lazily on first login. See `MANAR_WEB_BASE_URL`'s doc comment
   in `src/keycloak/keycloak.config.ts`.
5. Records `Tenant.keycloakRealm` / `keycloakIssuerUrl` / `keycloakClientId`
   and stores the generated client secret as a `SecretReference` row
   (`kind: KEYCLOAK_CLIENT_SECRET`, `provider: CONTROL_DB` — see "Storing
   the client secret" below).

`pnpm manar tenant:create` (the CLI, `src/cli/commands/tenant-create.command.ts`)
now calls `TenantProvisioningService.provisionTenant`, not
`TenantDatabaseManager.provisionTenant` directly — it's still the _only_
way to create a tenant this phase (Section 11).

### Storing the client secret

`SecretReference.provider` gains a new value, `CONTROL_DB`, alongside the
existing `ENV`/`OPENBAO` (see `prisma/control.prisma`'s doc comment).
Unlike the tenant database credential (`EnvSecretProvider`, an env var name
that's the _same_ across every tenant), a realm's client secret is
genuinely different per tenant and only exists once that tenant is
provisioned — a static env var can't name a value that doesn't exist yet.
`CONTROL_DB` stores the secret value directly in `SecretReference.reference`.

This is a known, deliberate limitation: the control DB has no field-level
encryption this phase, so this secret sits at the same trust boundary as
the rest of the control DB's provisioning metadata (plaintext at rest, but
never logged, never returned by any HTTP endpoint — there is no
cross-tenant admin surface to leak it through). It is also not read back by
anything at runtime this phase: JWT signature verification only needs the
realm's public JWKS, never the client secret — the secret is captured now
because Keycloak only returns/generates it once, at client-creation time,
and Phase 11's login redirect flow will need it. Phase 4/17's
`OpenBaoSecretProvider` replaces this with real encryption at rest without
any caller needing to change.

### Known limitation: partial provisioning failure

`TenantDatabaseManager.provisionTenant` already transitions the tenant to
`ACTIVE` before the Keycloak leg runs (see `docs/tenant-isolation.md` for
why: it's Phase 2's existing, unchanged contract). If the Keycloak leg
then fails, the tenant is left `ACTIVE` with a fully working, isolated
database but no realm (`keycloakRealm` stays `null`). Nothing else in the
system treats this tenant as broken — it just means `JwtAuthGuard` can
never resolve an issuer for it (`KnownIssuerRegistry` only matches tenants
with a non-null `keycloakIssuerUrl`), so no human can authenticate against
it yet. Consistent with Phase 2's own "no automatic rollback" stance, this
phase does not implement a retry path for the Keycloak leg alone — that's
future admin-tooling work. `TenantProvisioningService.provisionTenant`'s
doc comment covers this in more detail.

## Tenant DB schema additions

The first real models in what was an empty tenant schema
(`prisma/tenant.prisma`, Phase 2 → Phase 3):

- **`UserProfile`** — a local projection of a Keycloak-authenticated human
  identity (`id`, `keycloakSubject` unique — the JWT `sub` claim, `email`,
  `displayName`, `createdAt`, `lastSeenAt`). Never a credential store —
  Manar's own code never stores or sees passwords; Keycloak owns
  credentials entirely. Found-or-created by `JwtAuthGuard` the first time a
  given `keycloakSubject` is seen for that tenant.
- **`RoleBinding`** — `userId` (FK), `role` (the `Role` enum: the eight
  roles), `grantedAt`, `grantedBy`. A user can hold multiple roles (unique
  on `(userId, role)`).

Migration: `prisma/tenant/migrations/20260818181220_add_user_profile_and_role_binding`.

## Auth pipeline: `JwtAuthGuard`

`src/auth/jwt-auth.guard.ts` validates `Authorization: Bearer <JWT>`
against a **dynamic, per-issuer** JWKS endpoint — there is no single static
`jwksUri` (the realm, and therefore the JWKS URL, varies per tenant):

1. Extract the bearer token. Missing/malformed header → 401
   (`UnauthorizedException`, which Nest's default exception filter renders
   as `{ statusCode, message }` with no stack trace in the response body —
   stack traces are only ever logged server-side).
2. Read the token's `iss` claim **without verifying the signature yet**
   (`jose.decodeJwt` only base64-decodes the payload) — needed before
   verification because we don't yet know which realm's JWKS to trust.
3. Resolve that issuer against `KnownIssuerRegistry`
   (`src/auth/known-issuer-registry.service.ts`), which matches it against
   the control DB's `Tenant.keycloakIssuerUrl` column — an **allow-list**,
   never a blind trust of the token. No match (including any URL an
   attacker supplies that isn't a realm this deployment actually
   provisioned) → 401, and the guard never even attempts a JWKS fetch.
4. Fetch (and cache, per issuer — `JwksCacheService`) that realm's real
   JWKS and verify signature + expiry + issuer match
   (`jose.jwtVerify(token, jwks, { issuer })`). Any failure → 401.
5. Resolve the tenant's Prisma client
   (`TenantDatabaseManager.getClient(tenantId)`, Phase 2), find-or-create
   the `UserProfile` by `keycloakSubject`, reconcile `RoleBinding` rows to
   match the token's `realm_access.roles` claim (see "Role assignment"
   below), and attach an `AuthContext` (`src/auth/auth-context.ts`) to the
   request — the trustworthy identity every downstream module should key
   off, never a client-supplied tenant ID from a header/body/query param
   (Section 23). Controllers read it via the `@CurrentAuth()` decorator.

### Role assignment: Keycloak is the source of truth this phase

There is no Manar-side role-management API yet (out of scope — see
"Out of scope" below). `JwtAuthGuard` reconciles a user's `RoleBinding`
rows to match the verified token's `realm_access.roles` claim on every
authenticated request: it grants any role present in the token but missing
locally, and revokes any local binding for a role no longer present in the
token. A role change made in Keycloak (via its own admin console/API) takes
effect on the user's very next authenticated request — no separate sync
step. Only role names in `src/auth/roles.ts`'s `ROLES` list are ever
synced; unrelated Keycloak roles (e.g. Keycloak's own `offline_access`) are
ignored.

## `RolesGuard`

`src/auth/roles.guard.ts` + `@RequireRole('SECURITY_ADMIN')`
(`src/auth/require-role.decorator.ts`) — coarse, endpoint-level role
checks. Must run after `JwtAuthGuard`
(`@UseGuards(JwtAuthGuard, RolesGuard)`), since it reads the `AuthContext`
that guard attaches. A handler with no `@RequireRole(...)` is only gated
by `JwtAuthGuard` (any authenticated tenant user may call it). A user
lacking every listed role gets `403 Forbidden` (distinct from
`JwtAuthGuard`'s `401` — authenticated but not authorized).

Fine-grained, resource-scoped authorization (OpenFGA) is Phase 5 — not
built here.

## Local infra

`deploy/docker-compose.yml` adds a `keycloak` service (`quay.io/keycloak/keycloak:26.7.1`,
`start-dev` — Keycloak's current documented local-dev invocation; never
used in production). Host port `8081` (matching Postgres's non-default
`55432` pattern from Phase 2). Health checks hit the management port
(`9000` by default since Keycloak 26) via a raw `/dev/tcp` bash redirection,
since the image ships no `curl`/`wget`.

## Testing

`test/auth.e2e-spec.ts` runs all 6 mandatory scenarios from the design
spec against a real HTTP server, real local Postgres, and a real local
Keycloak (`pnpm infra:up`) — provisioning two real tenants with real
realms via `TenantProvisioningService`, and obtaining real, Keycloak-signed
tokens via the Resource Owner Password Credentials grant
(`test/support/keycloak-test-helpers.ts`) wherever a real flow is possible:

1. A valid token from a known tenant realm succeeds with the correct
   `AuthContext`.
2. A token with an unrecognized issuer, or an attacker-controlled signing
   key, is rejected. These two are the only fabricated tokens in the
   suite (`jose`'s `SignJWT` with a locally-generated key) — there is no
   way to produce either scenario against a real Keycloak by definition:
   one needs an issuer this deployment never provisioned, the other needs
   a token Keycloak itself would never sign.
3. A token valid for tenant A cannot be used to act as tenant B — verified
   both via the resulting `AuthContext.tenant.id` and by confirming no
   `UserProfile` was ever created in tenant B's isolated database for that
   Keycloak subject.
4. An expired token is rejected (a real realm's `accessTokenLifespan` is
   shortened to 1 second, a real token obtained, then used after it
   actually expires).
5. A missing or malformed `Authorization` header → 401, with the response
   body checked for the absence of a `stack` property or file-path-shaped
   stack frames.
6. `RolesGuard` denies a user with no `SECURITY_ADMIN` role (403) while
   still allowing that same, genuinely-authenticated user through an
   endpoint with no role requirement (200).

## Out of scope this phase

- Frontend login redirect flow (Phase 11) — the confidential client's
  `standardFlowEnabled: true` and stored secret exist for it, but nothing
  in `manar-web` changes this phase.
- OpenFGA fine-grained authorization (Phase 5).
- MFA configuration specifics (Keycloak-side, not Manar application code).
- SAML federation setup UI (the realm-per-tenant model supports it
  structurally; configuring a specific IdP is an operational task).
- A Manar-side role-management API/UI — role assignment happens in
  Keycloak; `JwtAuthGuard` only reflects it locally (see "Role assignment"
  above).
