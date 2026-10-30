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

## Add device: the one-liner

`POST /devices/install-code` (owner or security admin) creates an install key with `maxUses 1` and
`expiresAt` one hour out, in the group "My devices", after the plan's device cap check. The key's
secret is a 10-character code (alphabet without I, L, O, 0, 1): the tenant stores its SHA-256 like
any key, and the control DB (`install_codes`) maps the same hash to the tenant and the key id.
Neither keeps the code. The row is deleted when the code is used, when the key is revoked, and on
expiry. `GET /i/<code>` (PowerShell) and `GET /i/<code>.sh` (sh) are public, rate limited per
address (20 a minute) and return the bootstrap script with the code and tenant slug embedded;
fetching does not use the key. An unknown or expired code gets a script that prints that, with
HTTP 200. `/i/uninstall(.sh)` serve the uninstall scripts. `POST /hosts/register` accepts the code
in `installKey`: the control DB gives the tenant, the key is consumed, the row is deleted.

Config: `MANAR_CONSOLE_URL`, `MANAR_HOST_URL`, `MANAR_EDGE_VERSION`, `MANAR_EDGE_RELEASE_BASE`,
`MANAR_EDGE_SHA256_{WINDOWS_AMD64,LINUX_AMD64,LINUX_ARM64}` (see `.env.example`).

The device cap counts PENDING and APPROVED hosts. A new registration and a REJECTED -> APPROVED
approval both check it inside their own transaction under `pg_advisory_xact_lock`.

## Host channel: `/host/v1/*` (mTLS, :3443)

`HostAuthGuard` resolves the certificate SAN `host://<tenantSlug>/<machineId>` to a host in that
tenant's database and requires the exact certificate serial to be issued to it and unrevoked.
REJECTED and REVOKED hosts are refused; a PENDING host may call. Handlers read `@CurrentHost()`
(`hostId`, `tenantId`, `machineId`, `ownerSubject`, `status`). `GET /host/v1/config` returns
`{ hostId, status, startMode, features }`.

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

A rule must contain at least one **verified** condition: an address range (`cidrs`), `requireAdcs`,
`adOuDn` or `requireTpm`. A hostname pattern is the machine's own claim, so a rule with only a
hostname pattern, or with no condition at all, is refused with `400` on create and update (the rule
as it would be after the change is checked). Rules stored before this guard that break it are not
deleted: they are skipped when a host registers, and the console can show them as inactive.

`requireTpm` means **attested** TPM (see TPM attestation). A host's `keyType` is stored as `TPM` only
when attestation passed; otherwise `SOFTWARE`, whatever the installer reported.

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

## Key-less enrolment with an AD CS computer certificate

`POST /hosts/register/adcs` (public) for domain-joined Windows. Body: `tenantSlug`, `certificates`
(computer certificate first, then intermediates, PEM), `csr`, `machineId`, `os`, `keyType`,
`timestamp`, `signature`, optional `tpmChallengeId`.

- **Proof, not mTLS.** The agent listener trusts only the Manar CA, and registration is the step
  before a host has a Manar certificate. So the certificate's key signs
  `manar-adcs-register-v2\n<tenantSlug>\n<machineId>\n<SHA-256 of the CSR's SPKI hex>\n<os>\n<keyType>\n<ISO time>`
  (RSA PKCS#1 v1.5 or ECDSA, SHA-256; time within 5 minutes).
- **Trust.** The chain must lead to a CA certificate the tenant stored (`/adcs/trusted-cas`), with
  every certificate in its validity window, issuers that are CAs with `keyCertSign`, path length
  respected, no critical extension this validator does not evaluate, intermediates that restrict
  EKU allowing Client Authentication, and the computer certificate carrying EKU Client
  Authentication. The tenant comes from `tenantSlug`, but only that tenant's CAs count.
- **Algorithms.** Chain certificates and the proof key: RSA 2048 bits or more, or EC P-256 / P-384;
  chain signatures RSA (PKCS#1 v1.5 or PSS) or ECDSA with SHA-256, SHA-384 or SHA-512 only.
- **Template allow-list (required tenant setting).** `PUT /adcs/settings` takes
  `allowedTemplateOids`: the AD CS certificate template OIDs (extension `1.3.6.1.4.1.311.21.7`) that
  count as machine certificates. **An empty list accepts no certificate**, so key-less enrolment is off
  until the tenant lists its computer template(s). Any other Client Authentication certificate that
  merely carries a DNS name (a user or service template) is refused.
- **Revocation.** CRL from the certificate's HTTP distribution points, fetched only after the chain
  is accepted, through the SSRF guard (no redirects, 5 s, 5 MB streamed with a cap; a private PKI
  host must be listed in `SSRF_ALLOWED_HOSTS`). When the leaf or the base CRL names a Freshest CRL
  (AD CS: weekly base plus daily delta) the delta is fetched the same way and must verify (same
  issuer and signature, current, built on a base CRL number no newer than the base held); its entries
  are added, and a delta that cannot be checked is unknown. A revoked certificate is refused. CRL missing,
  unreachable, stale or badly signed = unknown: the host registers `PENDING` and no rule approves
  it. OCSP and LDAP distribution points are not used.
- **Identity.** The certificate's DNS name (lower-cased) is the host's identity: unique per tenant,
  and the hostname. A second `machineId` for the same certificate, or another certificate claiming
  an existing `machineId`, gets `403`; a certificate claiming a host enrolled with an install key
  becomes a pending rekey for an admin.
- **Group from AD.** manar-api reads the computer's `distinguishedName` from the customer's AD over
  **LDAPS only** (server certificate and name verified against the configured CA, TLS 1.2+, a
  read-only account), looking up `dNSHostName` with exactly one match among enabled computer accounts (accounts with
  `userAccountControl` bit 2 set are excluded). `/adcs/ou-rules` maps an OU
  (DN suffix, longest match wins) to a host group. Unreachable AD, no match, an ambiguous match or
  an unmapped OU: the host goes to the tenant's default group, `PENDING`, never auto-approved.
  Auto-approval for these hosts needs a verified certificate (`good` revocation) **and** a mapped OU.
- **Moving OUs.** A known computer-certificate host follows its OU when it registers again and on
  `POST /adcs/resync` (admin; re-reads AD for every `PENDING`/`APPROVED` computer-certificate host
  and moves hosts, status untouched, each move audited). AD unreachable: nothing changes and the
  run reports `ad_unreachable`.
- **AD password.** Stored in OpenBao KV at `adcs/<tenantId>/ad-bind`, write-only through
  `PUT /adcs/settings`, never in Postgres, a log, an audit event or a response. Changing
  `ldapsUrl`, `bindDn` or `serverCaPem` requires sending `bindPassword` again (`400` otherwise), so
  the stored password is only ever sent to the server it was set for.

Entra/Intune devices are not covered here; they use install keys.

## TPM attestation

Credential activation, server side (`POST /hosts/tpm/challenge`, then `/hosts/tpm/activate`, then
register with `tpmChallengeId`, on either register route):

1. **Challenge** sends the EK certificate (then intermediates) and the base64 `TPMT_PUBLIC` of the
   host key (the key the CSR is for). The EK certificate must chain to a root the tenant accepts
   (`/tpm-trust-roots`); the EK must be RSA of at least 2048 bits; the host key must have
   `fixedTPM`, `fixedParent` and `sensitiveDataOrigin`. The server wraps a random secret with
   MakeCredential for that EK and that key's name and keeps only its SHA-256.
2. **Activate** returns the secret the TPM recovered with `TPM2_ActivateCredential`. Three wrong
   answers end the challenge; it lives 10 minutes.
3. **Register** with the challenge id: it must be verified, unused, for this `machineId` and for
   exactly the key in the CSR, and is consumed. Only then `tpmVerified` is true (kept while the key
   stays the same, reset when a rekey is approved).

**Trust roots.** No manufacturer roots are shipped. Add the roots (or the vendor intermediate) your
fleet's TPMs chain to with `POST /tpm-trust-roots` `{ label, certPem, purpose }` (`purpose` is `EK`, the default, or `AK`; a certificate can have one purpose) (audited; take them from
the TPM vendors' published EK root pages and verify the fingerprints yourself). Not covered: ECC
EKs, EK certificates fetched from a vendor service (the host sends them), and a real-TPM interop
run, which needs manar-edge.

### Azure Trusted Launch vTPM (AK certificate path)

An Azure vTPM has no EK certificate (NV `0x01C00002` is undefined). Azure writes an **AK
certificate** at NV `0x01C101D0` instead (chain: AK cert, `Azure Cloud Virtual TPM CA - 11`,
`Azure Cloud Virtual TPM CA 2025`, root `Azure Virtual TPM Root Certificate Authority 2023`). The host
proves its key with `TPM2_Certify` by that AK:

1. `POST /hosts/tpm/ak-challenge` `{ tenantSlug, machineId, akCertificates (PEM, AK cert first then
intermediates), hostKeyPublic (base64 TPMT_PUBLIC, same rules as above) }`. The AK chain is
   validated here, before any row is created; a bad chain gets a 400 and costs nothing. Reply
   `{ challengeId, nonce (base64, 32 bytes), expiresAt }`. The challenge is bound to that AK
   certificate; at most 3 open challenges per machine and AK certificate (counted and created in one serializable transaction), in addition to the global cap.
2. The host runs Certify with the AK as signing key, the host key as the object, and the nonce bytes
   as qualifying data, then `POST /hosts/tpm/ak-certify` `{ tenantSlug, challengeId, akCertificates
(the same chain), hostKeyPublic, certifyInfo (base64 TPMS_ATTEST), signature (base64
TPMT_SIGNATURE) }`. Reply `{ verified }`.
3. Register with `tpmChallengeId` as before.

`verified` is true only when: the AK certificate chains to a tenant TPM root **with purpose `AK`**
(roots added for EK certificates are not used here, and AK roots are not used for EK certificates),
every intermediate allows EKU `2.23.133.8.3` and the AK certificate carries it, the AK certificate is
not a CA and, if it states key usage, has digitalSignature; the AK is RSA (2048 bits or more) and its
RSASSA or RSAPSS (SHA-2) signature covers the attestation; the AK is the one bound at step 1; the
attestation is a certify (`TPM_GENERATED_VALUE`, `TPM_ST_ATTEST_CERTIFY`) whose `extraData` is the
nonce and whose certified name is the name of `hostKeyPublic` (same key as at the challenge, so the
CSR key); and the key has `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`. Anything else is `false`
(three tries per challenge, 10 minutes, one use). Not covered: ECC AKs, and the Azure intermediates,
which the host sends (they rotate; take them from the AK certificate's AIA URLs).

Read the AK certificate on the host: `tpm2_nvread 0x1c101d0 -C o -o ak.der`, then
`openssl x509 -inform DER -in ak.der -out ak.pem`. Add the Azure root to the tenant trust list
(download from
`https://www.microsoft.com/pkiops/certs/Azure%20Virtual%20TPM%20Root%20Certificate%20Authority%202023.crt`,
see the Trusted Launch FAQ) and check its SHA-256 before adding:
`E6:C5:96:B1:7F:8F:FE:FB:A5:C3:00:F7:14:CF:B1:26:0C:60:28:70:4E:CF:7B:EC:C4:AB:50:18:EF:B0:0E:95`:

```bash
openssl x509 -inform DER -in azure-vtpm-root-2023.crt -out root.pem
openssl x509 -in root.pem -noout -fingerprint -sha256   # must match the value above
# then POST /tpm-trust-roots { "label": "Azure vTPM Root 2023", "certPem": "<root.pem>", "purpose": "AK" }
```

The audit event is `host.tpm_verified` (`method: ak-certify`; `ekFingerprint` is the AK certificate's).
Azure vTPM attestation shows the key is in Azure's virtual TPM, which Microsoft's hypervisor
provides; a host admin on the VM can still use it. It is not the same assurance as a hardware EK.

## Admin API

Writes need `TENANT_OWNER` or `SECURITY_ADMIN`; reads also allow `AUDITOR`.

- `GET /hosts?status=&hostGroupId=&limit=&cursor=` (newest first, cursor-paginated)
- `POST /hosts/:id/approve|reject|revoke`
- `GET /install-keys`, `POST /install-keys`, `POST /install-keys/:id/revoke`
- `GET/POST/PATCH /host-groups`
- `GET/POST/PATCH /org-units` (a move under its own subtree is refused with `400`)
- `GET/POST/PATCH /host-approval-rules` (a verified condition is required)
- `GET/POST/DELETE /adcs/trusted-cas`, `GET/PUT /adcs/settings`,
  `GET/POST/PATCH/DELETE /adcs/ou-rules`, `POST /adcs/resync`, `GET/POST/DELETE /tpm-trust-roots`

## Audit

Every change is recorded in the same transaction as the change: `host.registered`,
`host.rekey_requested`, `host.approved`, `host.rejected`, `host.revoked`,
`install_key.created`, `install_key.revoked`, and `host_group.changed`, `org_unit.changed`,
`host_approval_rule.changed`, `adcs_trusted_ca.changed`, `adcs_settings.changed`,
`ad_ou_rule.changed`, `tpm_trust_root.changed` (actor, before and after; never the AD password),
`host.group_moved`, `adcs.resync_run`, `host.tpm_verified`.

## Not yet

The console screens (F2c), the host mTLS listener that checks `HostCertificate.revokedAt` on each
connection, OCSP, ECC EKs, and the manar-edge side of both enrolment paths.

## Secrets (watcher and vault)

Device side (mTLS, approved hosts only): `POST /host/v1/events` (batch of at most 100; types
`secret.touched`, `secret.vault.*`, `secret.watch.available|unavailable`; paths are masked again on the
server), `GET /host/v1/secrets/instructions`, `POST /host/v1/secrets/vault/report`,
`POST /host/v1/secrets/access`, `GET /host/v1/secrets/access/:id`.
Console: `GET /secrets/timeline`, `GET /secrets/overview`, `POST /secrets/vault/:hostId` and `/restore`
(body `{ kind: 'aws'|'ssh', ref }`), `GET /secrets/access`, `POST /secrets/access/:id/decide`.
`SecretAlertBus` (src/secrets/secret-alert-bus.ts) emits one alert per `secret.touched` for the
approvals/notifications track. Device feature flags read from `/host/v1/config`: `secrets.block`
(Linux deny, default off) and `secrets.vault.ssh` (ssh vault, default off).
