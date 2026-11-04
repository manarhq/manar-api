import { ERROR_REFERENCE_PATTERN } from '../../common/errors/error-reference';
import { normalizeEmail } from '../restrictions/fingerprints';

export type QueryKind =
  | 'reference'
  | 'stripe_invoice'
  | 'stripe_id'
  | 'email'
  | 'uuid'
  | 'text'
  | 'empty';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Stripe invoice ids, and invoice numbers in Stripe's default `PREFIX-0001` shape. */
const STRIPE_INVOICE = /^(in_[A-Za-z0-9]{6,}|[A-Z0-9]{8}-\d{4,})$/;
const STRIPE_ID = /^(cus|sub)_[A-Za-z0-9]{2,}$/;
export const MAX_QUERY = 120;

/** What one search-box query looks like (DESK spec §7.4); decides which lookups run. */
export function classifyQuery(raw: string): { kind: QueryKind; value: string } {
  const q = raw.normalize('NFKC').trim().slice(0, MAX_QUERY);
  if (!q) return { kind: 'empty', value: '' };
  const upper = q.toUpperCase();
  if (ERROR_REFERENCE_PATTERN.test(upper))
    return { kind: 'reference', value: upper };
  if (STRIPE_INVOICE.test(q)) return { kind: 'stripe_invoice', value: q };
  if (STRIPE_ID.test(q)) return { kind: 'stripe_id', value: q };
  if (UUID.test(q)) return { kind: 'uuid', value: q.toLowerCase() };
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) {
    const email = normalizeEmail(q);
    if (email) return { kind: 'email', value: email };
  }
  return { kind: 'text', value: q };
}
