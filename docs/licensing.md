# Licensing: signed offline licence, soft limits

Founder decision (October 2026): a signed licence file that can be verified offline, carrying the
customer, the expiry and the agent count. Past a limit it warns and alerts staff; it never stops
the product. It works air-gapped.

**Nothing is ever blocked.** No request path reads the licence to allow or deny. A bad, missing,
expired or exceeded licence changes only a status, a log line, four metrics and a console banner.
The licence is not a security control and is not on the decision path.

## Format

A compact JWS (`header.payload.signature`, base64url), algorithm EdDSA (Ed25519).

Header: `{"alg":"EdDSA","kid":"<kid>","typ":"JWT"}`. The `kid` names the public key that verifies it.

Payload:

| Claim        | Type                                                  | Meaning                                         |
| ------------ | ----------------------------------------------------- | ----------------------------------------------- |
| `v`          | `1`                                                   | Format version                                  |
| `lic`        | string                                                | Licence id, for example `LIC-0001`              |
| `sub`        | string                                                | Customer display name                           |
| `deployment` | `hosted` or `customer`                                | Where it runs                                   |
| `iat`        | Unix seconds                                          | Issued at                                       |
| `nbf`        | Unix seconds                                          | Valid from (five minutes of clock skew allowed) |
| `exp`        | Unix seconds                                          | Expires at                                      |
| `limits`     | `{ agents: number or null, tenants: number or null }` | Licensed amounts; `null` is unlimited           |
| `features`   | string array                                          | Licensed features (reported, not enforced)      |

## Status

Computed at boot, every hour, and within a minute of the licence file changing
(`src/licensing/license.service.ts`).

| Status              | When                                                                                                      |
| ------------------- | --------------------------------------------------------------------------------------------------------- |
| `missing`           | No licence configured, or the file cannot be read (`reason: file_unreadable`)                             |
| `invalid_signature` | Not a well-formed licence (`reason: malformed`) or the signature does not match (`reason: bad_signature`) |
| `unverifiable`      | Well formed, but no shipped public key has its `kid` (`reason: unknown_kid`)                              |
| `not_yet_valid`     | Verified, `nbf` is in the future                                                                          |
| `expired`           | Verified, `exp` has passed                                                                                |
| `over_limit`        | Verified, in date, usage above a licensed amount                                                          |
| `expiring`          | Verified, in date, under its limits, expires within 30 days                                               |
| `valid`             | Verified, in date, under its limits                                                                       |

Claims (customer, dates, limits, features) are reported only from a verified licence.

`not_yet_valid` is one status more than the first design listed: a correctly signed licence with a
future start (a renewal installed early) is neither expired nor badly signed, and calling it either
would mislead whoever reads the status.

### Usage

The limits are compared with:

- **tenants**: tenants with status `ACTIVE` in the control database (`Tenant` table);
- **agents**: agents with status `ACTIVE` (enrolled, not revoked or killed) in each of those
  tenants' databases (`Agent` table), summed.

These are the same sources as the fleet heartbeat's `tenantsActive` and `agentsActive` counts. A
tenant database that cannot be reached is skipped, so the agent count can only be low, never high.
If the control database cannot be read, usage is unknown and no limit is reported as exceeded.

### Deployment

A verified licence says whether the deployment is `hosted` or `customer`. Without one,
`MANAR_DEPLOYMENT` says (default `customer`). Set `MANAR_DEPLOYMENT=hosted` on every deployment we
run ourselves, so its tenants see no "no licence" banner.

## Configuration

| Variable             | Meaning                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------- |
| `MANAR_LICENSE_FILE` | Path to the licence file, typically a mounted Kubernetes Secret. Wins over `MANAR_LICENSE`. |
| `MANAR_LICENSE`      | The licence inline                                                                          |
| `MANAR_DEPLOYMENT`   | `hosted` or `customer` (default), used when no licence is verified                          |

All optional. The licence is not a secret (it only says what the customer bought), but a Secret is
the usual way to mount a file.

## Where the status shows

- **Log**: one structured line per status change, `event: license_status_changed` (warning unless
  `valid`), with ids, dates and counts, never the licence itself.
- **Metrics** (internal `METRICS_PORT`):
  - `manar_license_status{status}`: 1 for the current status, 0 for the others;
  - `manar_license_expiry_timestamp_seconds`: expiry of the verified licence, 0 when none;
  - `manar_license_limit{resource}`: licensed amount for `agents` and `tenants`; absent when
    unlimited or when no licence is verified;
  - `manar_license_usage{resource}`: current usage; absent when it could not be counted.
- **`GET /platform/v1/license`** (platform API, platform admin role): the full status, claims,
  limits and usage.
- **`GET /tenant/license`** (`TENANT_OWNER` or `SECURITY_ADMIN`): only `status`, `deployment`,
  `expiresAt`, `daysLeft` and `overLimit` (a boolean). No customer name, no limits, no counts, so one
  tenant never sees another's numbers. manar-web shows a banner from it.
- **CLI**: `node dist/cli.js license:verify <file>` (or `pnpm manar license:verify <file>`) prints
  the decoded payload and the status against the keys shipped in that image. It shows an
  unverified payload too, marked `verified: false`, so a licence can be diagnosed. It does not count
  usage. Exit code 0 for `valid` or `expiring`, 1 otherwise.

Not yet in the fleet heartbeat: manar-fleet validates the heartbeat with a strict schema, so a new
`license` section would make it reject every heartbeat from an updated API. Add it to manar-fleet's
`HeartbeatPayloadSchema` (and its ops report) first, deploy manar-fleet, then send it from here.

## Keys

Public keys live in `src/licensing/keys/<kid>.pub` (Ed25519 SPKI PEM) and ship in the image
(`nest build` copies them to `dist/licensing/keys/`). Several may be present for rotation. **No
production key is committed yet: until the founder adds one by merge request, every licence reports
`unverifiable`.** Private keys are never committed; tests generate their own keypair at run time.

### Generate the signing keypair (founder, offline)

On a trusted machine, ideally offline:

```sh
openssl genpkey -algorithm ed25519 -out manar-license-2026.pem
openssl pkey -in manar-license-2026.pem -pubout -out manar-license-2026.pub
```

- Store `manar-license-2026.pem` (the private key) in the password manager as a secure note or
  file, then delete it from disk. It never goes in a repository, a ticket, a chat or CI. Later it
  can move to OpenBao transit (sign without ever exporting the key).
- Commit `manar-license-2026.pub` as `src/licensing/keys/manar-license-2026.pub` in a merge
  request. The file name is the `kid`. Update the "ships no production key yet" test in
  `src/licensing/license.spec.ts` in the same MR.

### Issue a licence

`scripts/license-issue.mjs` needs only Node (no install, no network). It reads the private key
from a file or from stdin (`--key -`), never writes it anywhere, and prints the licence to stdout:

```sh
# key straight from the password manager, never on disk (1Password CLI shown as an example)
op read "op://Manar/licence signing key/manar-license-2026.pem" | \
  node scripts/license-issue.mjs --key - --kid manar-license-2026 \
    --lic LIC-0001 --sub "Customer name" --deployment customer \
    --expires 2027-10-31 --agents 50 --tenants 1 --features packs,watcher \
  > LIC-0001.jws
```

Options: `--not-before YYYY-MM-DD` (default now), `--agents` and `--tenants` take a number or
`unlimited` (default). Dates are midnight UTC.

Check it with an image that has the public key: `node dist/cli.js license:verify LIC-0001.jws`.

### Install a licence

```sh
kubectl -n <namespace> create secret generic manar-license --from-file=license.jws=LIC-0001.jws
```

Mount it into the manar-api pods and set `MANAR_LICENSE_FILE=/etc/manar/license/license.jws`. A
renewed licence is picked up within about a minute of the Secret update, with no restart.

### Rotate the signing key

Add the new `<kid>.pub` next to the old one and release. Issue new licences with the new `kid`.
Remove the old `.pub` only when no installed licence uses it any more.
