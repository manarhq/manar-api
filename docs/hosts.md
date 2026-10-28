# Hosts, install keys and approval

A **host** is a machine (laptop, server, VDI desktop) that runs Manar's agent-side components. It
sits between the tenant and its agents. Code: `src/hosts/`. Records: `prisma/tenant.prisma`
(`Host`, `HostCertificate`, `HostGroup`, `OrgUnit`, `InstallKey`, `HostApprovalRule`).

## Install keys

- Format `mik_<tenantSlug>_<43 base64url chars>`, 256 random bits. The prefix decides the
  tenant, so a host never picks its own tenant.
- Shown once, in the `POST /install-keys` response. Stored only as its SHA-256; never listed,
  never logged (logs carry the key id).
- Scoped to one host group, with optional limits: `allowedCidrs` (IPv4/IPv6, IPv4-mapped IPv6
  normalised, malformed ranges refused on create), `maxUses`, `expiresAt`. Revocable.
- A key registers machines and grants nothing else. One use is taken by a single conditional
  `UPDATE … RETURNING` (not revoked, not expired, under `maxUses`), so concurrent registrations
  never exceed the limit. Every refusal returns the same `401 install key is not valid`.

## Registration: `POST /hosts/register` (public)

Body: `installKey`, `csr`, `machineId` (`[A-Za-z0-9._-]{1,128}`), `hostname`, `os`, `keyType`
(`TPM` | `SOFTWARE`; a software key is a warning, not a block).

1. The tenant comes from the key prefix; it must be `ACTIVE`.
2. The CSR must carry exactly one SAN, the URI `host://<tenantSlug>/<machineId>`, and nothing else.
3. The key use is taken (above).
4. In one tenant transaction, by `machineId` (unique per tenant):
   - **new machine**: created, bound to the CSR's key (SHA-256 of its SPKI), `APPROVED` if an
     approval rule matches, else `PENDING`;
   - **known machine, same key and group** (VDI re-registration): merged, status kept;
   - **known machine, different key or another group's key**: nothing about the machine
     changes; the request is recorded as a pending rekey (`host.rekey_requested`) and the call
     returns `409 host_rekey_pending` with no certificate. Only one rekey waits at a time; a
     later one does not replace it but is recorded too, marked `conflictsWithPending`;
   - **REVOKED or REJECTED**: `403`, no certificate.
5. A host certificate is issued from the OpenBao CA. If the host was revoked, rejected or rekeyed
   while the CA was signing, the new certificate is revoked at once and the call is refused.

An install key alone can therefore neither take over nor disturb a machine already registered.

## Approval

Rules (`/host-approval-rules`) auto-approve a new machine when every set condition matches:
group (or every group), hostname glob (hostname characters plus `*`/`?`, at most three `*`,
matched in linear time), address range, and `keyType: TPM`. Otherwise the host waits for a person.

`keyType` is what the installer reports; there is no TPM attestation yet, so `requireTpm` keeps
honest installers on software keys out of auto-approval but does not stop a caller holding the
install key from claiming `TPM`. Treat the install key as the control and `requireTpm` as a filter.

**Caller address.** Install-key ranges and rule ranges use the caller's address only when
`MANAR_TRUSTED_PROXY_CIDRS` names the proxies in front of the API (or is `none` for an API exposed
directly). Unset, `request.ip` may be the proxy pod, so the address is recorded as `unknown` and no
range matches: a key with ranges refuses every host and a rule with ranges never auto-approves.

| Action                    | From                  | To         | Notes                                           |
| ------------------------- | --------------------- | ---------- | ----------------------------------------------- |
| `POST /hosts/:id/approve` | `PENDING`, `REJECTED` | `APPROVED` |                                                 |
| `POST /hosts/:id/reject`  | `PENDING`             | `REJECTED` | drops a pending rekey                           |
| `POST /hosts/:id/revoke`  | `PENDING`, `APPROVED` | `REVOKED`  | revokes its certificates; drops a pending rekey |

With a rekey pending, `approve` needs body `{ "keyFingerprint": "<the host's pendingKeyFingerprint>" }`
and the host `PENDING` or `APPROVED`; it binds the new key and group and revokes the old key's
certificates. `reject` drops the request.

Certificate revocation is local first (enforced immediately), then at OpenBao in its colon-hex
serial format; `caRevokedAt` records OpenBao's confirmation and unconfirmed serials are retried
on the next revocation for that host.

## Admin API

Writes need `TENANT_OWNER` or `SECURITY_ADMIN`; reads also allow `AUDITOR`.

- `GET /hosts?status=&hostGroupId=&limit=&cursor=` (newest first, cursor-paginated)
- `POST /hosts/:id/approve|reject|revoke`
- `GET /install-keys`, `POST /install-keys`, `POST /install-keys/:id/revoke`
- `GET/POST/PATCH /host-groups`
- `GET/POST/PATCH /org-units` (a move under its own subtree is refused with `400`)
- `GET/POST/PATCH /host-approval-rules`

## Audit

Every change is recorded in the same transaction as the change: `host.registered`,
`host.rekey_requested`, `host.approved`, `host.rejected`, `host.revoked`,
`install_key.created`, `install_key.revoked`, and `host_group.changed`, `org_unit.changed`,
`host_approval_rule.changed` (actor, before and after).

## Not yet

Org-unit sync from AD/Entra and AD CS enrolment (F2b), the console screens (F2c), and the host
mTLS listener that checks `HostCertificate.revokedAt` on each connection.
