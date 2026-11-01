# Billing and entitlements

- Plan table and limits: `src/billing/plans.ts`. `EntitlementsService.get(tenantId)` returns plan, status, limits (`null` = unlimited), features. No row = free.
- Create under a cap with `EntitlementsService.withinLimit(...)` (count, check, create in one tenant-DB transaction under an advisory lock). `assertWithin(tenantId, limit, current)` is for read-only checks; `current` is how many exist now, so one more must fit. Both throw `PlanLimitError` (403 `plan_limit_reached`, with `limit`, `current`, `max`, `upgradeUrl`).
- A company trial past `trialEndsAt` reads as `read_only`: `ReadOnlyInterceptor` refuses console writes (403 `workspace_read_only`); `/billing`, `/evidence` and reads stay open.
- Stripe: `POST /billing/checkout`, `POST /billing/portal`, `GET /billing`, public `POST /billing/stripe/webhook` (raw body, signature, event ids stored in `stripe_events`). The tenant is found from the stored Stripe customer id; event metadata may only agree with it.
- Company: the worker's `CompanyQuantityService` runs daily and sets the per-user and extra-device item quantities.
- Downgrade: nothing is removed. Enrolled devices stay protected; `withinLimit`/`assertWithin` refuse new ones over the cap; audit older than the plan window is hidden by the search floor, not deleted.
- Config: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` (ExternalSecrets), `STRIPE_PRICE_PRO_MONTHLY`, `STRIPE_PRICE_PRO_YEARLY`, `STRIPE_PRICE_COMPANY_USER`, `STRIPE_PRICE_EXTRA_DEVICE`, `BILLING_CONSOLE_URL`. The statement descriptor is the Stripe account's public business name (Fixio).

## Launch offer (growth track)

First 100 personal sign-ups that add an approved device get Pro for 3 months with no card. The slot is
claimed under `pg_advisory_xact_lock` (one per person and per device hash; unique indexes back it up),
then a Pro monthly subscription is created with `trial_end` and `missing_payment_method: cancel`, so
it ends cleanly into the free plan unless a card is added in the portal. A Stripe failure gives the
slot back. Counter: `GET /public/launch-offer` (cached 15 s, rate limited). Off: `LAUNCH_OFFER_ENABLED=false`.

## Existing tenants (pilot and demo)

Without an entitlement row a tenant reads as Free. Migration `20261101140000_manual_company_entitlements`
adds `tenant_entitlements.manual` and gives every existing COMPANY tenant that has no row a `company`
plan, `active`, no Stripe ids, `manual = true`. It is idempotent (re-run the INSERT any time), skips
PERSONAL and SAMPLE tenants and any tenant that already has a row, and Stripe events never touch these
rows (they find tenants by Stripe customer id). Rollback: `DELETE FROM tenant_entitlements WHERE manual;`.
