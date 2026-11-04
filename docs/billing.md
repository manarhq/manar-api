# Billing and entitlements

Pay-as-you-go hybrid pricing. Design: workspace `docs/superpowers/specs/2026-11-04-payg-pricing-design.md`.

## Plans

- Table: `src/billing/plans.ts`. `EntitlementsService.get(tenantId)` returns plan, status, limits (`null` = unlimited), features and the monthly allowance. No row = Free.
- Free: 1 device, 20 AI actions a month, 30-day history, no cloud agents. Personal trial (`trial`): Free with up to 3 devices for 14 days, then it reads as Free with no job. Pro: $5 a month (or $50 a year), 2 active devices included, $2 per extra active device, 300 AI actions and 300 cloud-agent minutes. Company: $15 per active seat a month (at least 3) or $150 per seat a year committed; 300 AI actions and minutes per seat, pooled. Company trial: 30 days, 25 devices, card collected through Checkout.
- `frozen` (a card dispute is open): Free limits and allowance, plan name kept, safety untouched. A won dispute restores `active`.
- Caps: `EntitlementsService.withinLimit(...)` (count, check, create under an advisory lock) and `assertWithin(...)` throw `PlanLimitError` (403 `plan_limit_reached`). A lapsed company trial is `read_only` (`ReadOnlyInterceptor`).

## Active devices and seats

A device or seat is active with 3 or more different UTC days online in a calendar month. The hourly Growth tick (`BillingTickService`) records days from `hosts.lastSeenAt` and `user_profiles.lastSeenAt` (26-hour look-back) into `active_days`, then queues Stripe meter units in `meter_reports` as `target - already reported` and sends them with their identifier. Stripe down leaves them queued. Ownerless devices are not seats.

## Usage meter and credit wallet

- `UsageMeterService.consume(tenantId, kind, key)`: allowance first, then credits (oldest expiry first) within the monthly cap, in one control-DB transaction under a per-tenant lock. Refusals are 402 (`allowance_used`, `credits_exhausted`, `spend_cap_reached`, `paid_features_paused`); an error is 503 `metering_unavailable`. `ai(tenantId, fn)` wraps one AI action and gives it back when no answer came.
- Metered: the console assistant, incident summary, policy suggestion and AI audit investigation (one AI action each) and cloud-agent MCP calls (one minute per agent per UTC minute). Never metered: anything on the decision, approval, device, vault, kill-switch or audit path (`decision-path-dependencies.spec.ts`, "safety is never metered").
- Credits: $5 = 1,000, valid 12 months (`credit_lots`). Bought with a one-time Checkout (`POST /billing/credits`) or by auto top-up (2 packs when under 400 credits, at most 3 a month, an invoice charged to the saved card). Lots are added by the webhook from the paid line items, keyed by the Stripe id.
- Cap: Pro defaults to 4,000 credits ($20) a month, Company to 10,000 ($50) until an owner sets one (`PUT /billing/wallet`).
- Alerts: 50/80/100% of the allowance and of the cap, and low credits, emailed once per month per key (`UsageAlertsService`); the console banner comes from `GET /billing/usage`.

## Stripe

- Catalog: `node scripts/stripe-catalog.mjs` (test mode; `--live` for live) creates the products, the prices by lookup key (`manar_*_v2`) and the two meters. No price id is configured.
- Endpoints: `GET /billing`, `GET /billing/usage`, `POST /billing/checkout` (`pro_monthly`, `pro_yearly`, `company_monthly`, `company_yearly` + `seats`, `company_trial`), `POST /billing/credits`, `PUT /billing/wallet`, `POST /billing/portal`, public `POST /billing/stripe/webhook`.
- Webhook: signature on the raw body; the tenant comes only from the stored Stripe customer id; an event id is recorded after it is applied. Handles subscription and invoice events, paid credit Checkouts, paid top-up invoices and disputes. Yearly plans get their monthly metered item added here (Checkout cannot mix intervals; subscriptions use `billing_mode: flexible`).
- Config: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` (ExternalSecrets), `BILLING_CONSOLE_URL`. The old `STRIPE_PRICE_*` variables are no longer read.

## Launch offer (retired)

The "first 100 get Pro for 3 months" offer is replaced by the 14-day personal trial. Its claims were copied into `trial_claims` so nobody gets both. `pnpm manar billing:retire-launch-offer` ends the remaining trials on the old $9 price without renewing (or moves a kept one to the new $5 price). Run once per environment.

## Existing tenants (pilot and demo)

Migration `20261101140000_manual_company_entitlements` gives every pre-existing COMPANY tenant a manual `company` row that Stripe events never touch. Rollback: `DELETE FROM tenant_entitlements WHERE manual;`.
