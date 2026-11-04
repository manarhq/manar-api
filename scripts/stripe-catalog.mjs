#!/usr/bin/env node
// Creates the pay-as-you-go Stripe catalog (workspace spec 2026-11-04-payg, section 4.1):
// products, prices (by lookup key) and Billing Meters. Idempotent: what exists is left alone.
//
//   STRIPE_SECRET_KEY=... node scripts/stripe-catalog.mjs          # test mode only
//   STRIPE_SECRET_KEY=... node scripts/stripe-catalog.mjs --live   # live mode (founder action)
//
// The key is read from the environment and never printed. Without --live a live key is refused.
import Stripe from 'stripe';

const key = process.env.STRIPE_SECRET_KEY?.trim();
const live = process.argv.includes('--live');
if (!key) {
  console.error('STRIPE_SECRET_KEY is not set');
  process.exit(1);
}
if (/^(sk|rk)_live_/.test(key) && !live) {
  console.error('Refusing a live key without --live');
  process.exit(1);
}
const stripe = new Stripe(key, { apiVersion: '2026-09-30.endive' });

const METERS = [
  { event_name: 'manar_pro_extra_devices', display_name: 'Manar Pro extra active devices' },
  { event_name: 'manar_company_seats', display_name: 'Manar Company active seats' },
];

/** One product per plan, so every invoice line names what it is. */
const PRODUCTS = [
  {
    id: 'manar_pro',
    name: 'Manar Pro',
    prices: [
      { lookup_key: 'manar_pro_monthly_v2', unit_amount: 500, recurring: { interval: 'month' } },
      { lookup_key: 'manar_pro_yearly_v2', unit_amount: 5000, recurring: { interval: 'year' } },
    ],
  },
  {
    id: 'manar_pro_extra_device',
    name: 'Manar Pro extra active device',
    prices: [
      {
        lookup_key: 'manar_pro_extra_device_v2',
        unit_amount: 200,
        recurring: { interval: 'month', usage_type: 'metered' },
        meter: 'manar_pro_extra_devices',
      },
    ],
  },
  {
    id: 'manar_company',
    name: 'Manar Company',
    prices: [
      {
        lookup_key: 'manar_company_seat_monthly_v2',
        unit_amount: 1500,
        recurring: { interval: 'month', usage_type: 'metered' },
        meter: 'manar_company_seats',
      },
      { lookup_key: 'manar_company_seat_yearly_v2', unit_amount: 15000, recurring: { interval: 'year' } },
    ],
  },
  {
    id: 'manar_ai_credits',
    name: 'Manar AI credits (1,000)',
    prices: [{ lookup_key: 'manar_credits_1000_v2', unit_amount: 500 }],
  },
];

const meters = new Map();
for await (const m of stripe.billing.meters.list({ status: 'active' })) meters.set(m.event_name, m.id);
for (const m of METERS) {
  if (meters.has(m.event_name)) continue;
  const made = await stripe.billing.meters.create({
    ...m,
    default_aggregation: { formula: 'sum' },
    customer_mapping: { type: 'by_id', event_payload_key: 'stripe_customer_id' },
    value_settings: { event_payload_key: 'value' },
  });
  meters.set(m.event_name, made.id);
  console.log(`meter ${m.event_name} created`);
}

const existing = new Set(
  (
    await stripe.prices.list({
      lookup_keys: PRODUCTS.flatMap((p) => p.prices.map((x) => x.lookup_key)),
      limit: 100,
    })
  ).data.map((p) => p.lookup_key),
);
for (const p of PRODUCTS) {
  let product = await stripe.products.retrieve(p.id).catch(() => null);
  product ??= await stripe.products.create({
    id: p.id,
    name: p.name,
    // SaaS for business use: Stripe Tax applies UAE VAT for UAE buyers.
    tax_code: 'txcd_10103001',
  });
  for (const price of p.prices) {
    if (existing.has(price.lookup_key)) continue;
    await stripe.prices.create({
      product: product.id,
      currency: 'usd',
      tax_behavior: 'exclusive',
      lookup_key: price.lookup_key,
      unit_amount: price.unit_amount,
      ...(price.recurring
        ? {
            recurring: {
              ...price.recurring,
              ...(price.meter ? { meter: meters.get(price.meter) } : {}),
            },
          }
        : {}),
    });
    console.log(`price ${price.lookup_key} created`);
  }
}
console.log(`catalog ready (${live ? 'live' : 'test'} mode)`);
