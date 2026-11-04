# Enterprise and Government "invisible mode" (src/enterprise)

Spec: workspace `docs/superpowers/specs/2026-11-04-enterprise-invisible-mode-design.md`. Plan:
`docs/superpowers/plans/2026-11-04-enterprise-phase1.md`. The browser extension (WATCH) lives in
`manarhq/manar-browser`.

## Switching it on (staff only)

A tenant is in enterprise mode only when all three hold; otherwise every route below answers 404:

1. the tenant is `ACTIVE`;
2. its catalog flag `enterprise` is on (`PATCH /platform/v1/tenants/:id/catalog` with
   `{"features":{"enterprise":true}}`). **Default off**, the only catalog flag that is;
3. it has an `enterprise_profiles` row (sector `ENTERPRISE` or `GOVERNMENT`, public slug).

A catalog or control-DB read failure is 503 `enforcement_dependency_unavailable`, never "on".

## Routes in this slice

| Route                             | Auth                                               | Notes                                                                                                                      |
| --------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `POST /watch/v1/enrol`            | enrolment key (SHA-256 stored, expiry, revocation) | P-256 public JWK only; same key, same device; the claimed profile email links the person **unverified**                    |
| `GET /watch/v1/policy?since&wait` | device signature                                   | 200 with the policy, or 204 when unchanged; holds up to 25 s                                                               |
| `POST /watch/v1/heartbeat`        | device signature                                   | versions, config hash, tamper hints (unpacked copy, changed managed config), hostname-only visit counts                    |
| `POST /watch/v1/events`           | device signature                                   | strict schema: categories, counts, rule trace; any other field (a prompt) is 400                                           |
| `POST /watch/v1/identity/nonce`   | device signature                                   | single-use nonce bound to the device, 10 min; 404 until `ENT_WATCH_OIDC_ISSUER` is set                                     |
| `POST /watch/v1/identity`         | device signature                                   | id_token: issuer JWKS, `iss`, `aud`, `exp`, age 10 min, nonce burned once for this device, Entra `tid` equals the tenant's |

Device signature (R11): headers `x-watch-tenant`, `x-watch-device`, `x-watch-time` (ms),
`x-watch-sig` = base64url(ECDSA P-256 SHA-256, IEEE P1363) over
`METHOD\nPATH\nTIME\nsha256hex(raw body)`, window 120 s. Needs Fastify `rawBody` (on in `main.ts`).

## Security checklist (every check: what else could skip it, and does it deny on error)

| Check                | Other path that could skip it                                                                                                                                           | On error  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| Enterprise gate      | Every controller in `src/enterprise` calls it (enrol directly, others through `DeviceSignatureGuard`); no other module writes `ent_*` tables                            | 503       |
| Enrolment key        | Only `enrol` creates devices                                                                                                                                            | 503       |
| Device signature     | All `/watch/v1` routes but `enrol` carry the guard; a device id is looked up in the header tenant's own database only, so a device of tenant A never signs for tenant B | 401 / 503 |
| Body without content | Zod `.strict()` on every body; 400 lists field paths, never values                                                                                                      | 400       |
| Identity binding     | Only `verifyIdentity` sets `identityVerified`; nonce burned with one conditional update                                                                                 | 401 / 503 |

## Environment

| Variable                   | Default                          | Meaning                                                                                   |
| -------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------- |
| `ENT_CONSOLE_URL`          | `https://console-manar.fixio.ae` | Base of the public page link in the policy                                                |
| `ENT_WATCH_OIDC_ISSUER`    | unset (identity proof off)       | Keycloak realm issuer with the Microsoft IdP                                              |
| `ENT_WATCH_OIDC_CLIENT_ID` | `manar-watch`                    | Public client for the silent sign-in (needs a Keycloak client per realm: infra follow-up) |

## Migrations and rollback

- Control `20261105090000_enterprise_profiles`: enum `EnterpriseSector`, table `enterprise_profiles`.
- Tenant `20261105090000_enterprise_core`: `ent_settings`, `ent_people`, `ent_enrol_keys`,
  `ent_devices`, `ent_identity_nonces`, `ent_events`, `ent_tamper_signals`, `ent_site_visits`.
  Run `pnpm manar tenants:migrate` after deploying.
- Both are additive. Rollback: revert the code; the tables can stay (nothing reads them) or be
  dropped with the enum once no tenant uses the mode.

## Not in this slice

Rules and templates, exceptions and grants, capture store, investigations, Teams and email, Graph
sync, dashboard and reports, the public page data: plan Tasks 10 and 12 to 20.
