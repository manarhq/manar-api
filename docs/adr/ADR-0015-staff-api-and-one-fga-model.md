# ADR-0015 — Staff API on its own listener, authorised by one OpenFGA model

- **Status:** ACCEPTED
- **Date:** 2026-11-04
- **Phase:** DESK Phase 1 (staff console rebuild)
- **Deciders:** Mohamed (AC-1, AC-2, engine choice); engineering judgement (AC-6, AC-7, AC-29, AC-30)

## Context

The staff console (DESK, manar-admin) needs to read and act on customer accounts. Until now it
read other services with realm roles from the staff token, and no customer could see a staff look.
The founder decided (4 Nov 2026) that Entra decides who may enter, that roles, groups and
permissions are managed in the console, that OpenFGA is the one engine for staff and customers,
and that every staff view or action appears in the customer's audit log.

## Decision

- Staff routes live under `/staff/v1` on a third Fastify app (`src/staff/staff-app.module.ts`,
  port `STAFF_PORT`, default 3200), started only when `STAFF_ENABLED=true`. No ingress routes it;
  a NetworkPolicy admits only DESK pods (infra).
- `StaffAuthGuard` accepts only a vax-staff access token for `manar-admin`, audience
  `manar-api-staff`, `idp=entra`, Fixio's `entra_tid`, and an ACTIVE `staff_members` row bound by
  the token's `entra_oid`. Binding is by a stable id only (an object id recorded at invite, or
  a one-time invite token); an email claim never binds.
- `StaffPermissionGuard` is default deny: a route without `@RequirePermission` or
  `@StaffSignedIn` is refused. Checks go to OpenFGA (`platform:manar#<permission>`) with
  `current_time` context, never cached; OpenFGA unreachable is 503.
- Staff RBAC tuples (`staff`, `group`, `role`, `platform`, condition `within_window`) sit in the
  same model file as agent grants. Postgres is the source of truth; every write path and the
  reconciler go through one per-(principal, role) lock and one projection.
- Every staff route writes the hash-chained `staff_audit_events` (signed checkpoints, OpenBao
  anchor); every staff view or action on a workspace writes a `staff` actor event into that
  workspace's own chain.

## Alternatives considered

- A `/staff` prefix on the public human listener: one routing rule from the internet. Rejected
  (AC-6).
- A separate staff database: every index query would join across databases, and restrictions
  must be read on every token verification. Rejected (AC-7).
- Realm roles in the staff token: a second source of truth. Rejected by the founder.

## Consequences

One process serves three listeners. The control schema now holds staff RBAC, the staff audit
chain and account restrictions (its header says so). Restriction lookups add one indexed query
to every customer token verification. Rollback: `STAFF_ENABLED=false` turns the staff listener
off; the migrations are additive.

## Enforcement-label impact

None. A restricted account is refused before any decision is made; no label changes.
