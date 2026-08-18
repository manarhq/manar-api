# Phase 3: Human Authentication — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only (frontend Keycloak redirect flow is Phase 11 /
Section 67, once real pages exist to protect)
Depends on: Phase 2 (control/tenant DB split, `TenantDatabaseManager`,
provisioning CLI)

## Purpose

Wire Keycloak as the human identity provider (Section 12) and establish
trustworthy, tenant-scoped route protection (Section 67). No SOC UI yet —
this phase is the backend auth mechanism only.

## Realm model

**One Keycloak realm per tenant.** Rationale: matches the DB-per-tenant
isolation philosophy, lets each tenant bring its own SSO/SAML federation
(decision #14) without touching other tenants' auth config, and makes the
JWT `iss` (issuer) claim itself a trustworthy, cryptographically-verified
signal of which tenant a request belongs to — satisfying Section 23's
"never trust tenant identity from an untrusted request body; derive it
from authenticated credentials." A Keycloak master-realm admin is an
infrastructure operator (Section 11 already accepts this), not an
application-level super admin — Manar's own code never exposes a
cross-tenant view.

Realm provisioning becomes part of tenant provisioning: extend the
`TenantProvisioningService` introduced conceptually in Phase 2 (or
introduce it now if Phase 2 only built the DB half) to also create a
realm via Keycloak's Admin REST API, seed the eight application roles
(Section 11: Tenant Owner, Security Admin, AI Governance Manager, SOC
Operator, Approver, Auditor, Developer, Read Only) as realm roles, and
create a confidential client for `manar-api` to validate tokens against.

## Local infra addition

Add Keycloak to `deploy/docker-compose.yml` (current official Keycloak
container image/start command — research at implementation time, Keycloak
has changed its recommended `start-dev` invocation across versions).

## Data model (tenant DB — `prisma/tenant.prisma`)

First real models in the tenant schema (Section 70):

- `UserProfile`: `id`, `keycloakSubject` (unique — the JWT `sub` claim),
  `email`, `displayName`, `createdAt`, `lastSeenAt`. This is a local
  projection of the Keycloak identity, not a credential store — Manar
  never stores or sees passwords.
- `RoleBinding`: `userId` (FK), `role` (enum of the eight roles above),
  `grantedAt`, `grantedBy`. A user can hold multiple roles.

Create and apply the migration.

## Auth pipeline

1. Incoming request carries `Authorization: Bearer <JWT>`.
2. A guard validates the JWT signature against the issuing realm's JWKS
   endpoint. Since realm (and therefore JWKS URL) varies per tenant, use
   a dynamic per-issuer JWKS resolver keyed by the token's unverified
   `iss` claim, restricted to an allow-list of issuers this deployment
   actually knows about (never fetch an arbitrary attacker-supplied JWKS
   URL — resolve `iss` back to a known `Tenant` row in the control DB
   first, reject if no match, only fetch that tenant's real Keycloak
   realm's JWKS from server-side config, not from the token itself).
3. On valid signature + expiry, resolve the `Tenant` from the issuer,
   `getClient(tenantId)` from `TenantDatabaseManager` (Phase 2), find-or-
   create the `UserProfile` by `keycloakSubject`, load `RoleBinding`s.
4. Attach an `AuthContext` (tenant, user, roles) to the request, available
   to controllers via a decorator — this is the trustworthy identity
   context Section 23 requires for everything downstream (agents, tasks,
   authorization all key off this, not off client-supplied tenant IDs).
5. A `RolesGuard`/decorator (`@RequireRole('SECURITY_ADMIN')`) for
   endpoint-level authorization — coarse role checks only; fine-grained
   OpenFGA-based authorization is Phase 5, not built here.

## Testing

- JWT with a valid signature from a known tenant's realm → request
  succeeds, correct `AuthContext` attached.
- JWT signed by an unrecognized/attacker-controlled key (self-signed,
  wrong issuer) → rejected, fails closed.
- JWT valid for Tenant A cannot be used to act as Tenant B (issuer/realm
  mismatch is the enforcement point — verify explicitly).
- Expired JWT → rejected.
- Missing/malformed `Authorization` header → 401, no stack trace leaked.
- `RolesGuard` denies a user lacking the required role.

## Out of scope this phase

- Frontend login redirect flow (Phase 11)
- OpenFGA fine-grained authorization (Phase 5)
- MFA configuration specifics (Keycloak-side, not Manar application code)
- SAML federation setup UI (later; the realm-per-tenant model supports it
  structurally, configuring a specific IdP is an operational task)
