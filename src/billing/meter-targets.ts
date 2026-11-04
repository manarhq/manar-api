import { METER, type MeterName } from './stripe.gateway';
import {
  COMPANY_MIN_SEATS,
  PRO_INCLUDED_DEVICES,
  type PlanName,
} from './plans';

/**
 * How many units a month should have billed so far (workspace spec 2026-11-04-payg, 4.2). Meters
 * sum what is reported, so the tick reports `target - already reported` and never a decrease.
 *
 * - Pro: active devices beyond the 2 included.
 * - Company monthly: active seats, at least 3 once the subscription is live in the month.
 * - Company yearly: active seats beyond the committed number (itself at least 3).
 */
export function meterTarget(
  plan: PlanName,
  active: number,
  committedSeats: number | null,
): { meter: MeterName; target: number } | null {
  if (plan === 'pro')
    return {
      meter: METER.PRO_EXTRA_DEVICES,
      target: Math.max(0, active - PRO_INCLUDED_DEVICES),
    };
  if (plan !== 'company') return null;
  if (committedSeats)
    return {
      meter: METER.COMPANY_SEATS,
      target: Math.max(0, active - Math.max(COMPANY_MIN_SEATS, committedSeats)),
    };
  return {
    meter: METER.COMPANY_SEATS,
    target: Math.max(COMPANY_MIN_SEATS, active),
  };
}

/** UTC calendar day of a timestamp, as a Date at 00:00 (for a DATE column). */
export function dayOf(at: Date): Date {
  return new Date(
    Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate()),
  );
}
