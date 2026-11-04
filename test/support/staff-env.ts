import 'dotenv/config';
import { randomUUID } from 'node:crypto';

/**
 * Imported first by staff e2e specs (ConfigModule validates the environment when the module
 * graph loads): a throwaway staff realm, Entra tenant id, OpenFGA store and audit chain per run.
 */
export const STAFF_E2E_SUFFIX = randomUUID().slice(0, 8);
export const STAFF_E2E_REALM = `staff-e2e-${STAFF_E2E_SUFFIX}`;
export const STAFF_E2E_TID = randomUUID();
export const CUSTOMER_E2E_REALM = `cust-e2e-${STAFF_E2E_SUFFIX}`;
const base = process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';
export const CUSTOMER_E2E_ISSUER = `${base}/realms/${CUSTOMER_E2E_REALM}`;
// The customer realm stands in for the shared hosted realm `manar` (AUTH_ISSUERS), so staff pages
// read real Keycloak data and restricted customers get real tokens.
process.env.AUTH_ISSUERS = CUSTOMER_E2E_ISSUER;

process.env.STAFF_ENABLED = 'true';
process.env.STAFF_OIDC_ISSUER = `${base}/realms/${STAFF_E2E_REALM}`;
process.env.STAFF_ENTRA_TENANT_ID = STAFF_E2E_TID;
process.env.OPENFGA_STORE_NAME = `staff-e2e-${STAFF_E2E_SUFFIX}`;
process.env.STAFF_AUDIT_CHAIN_ID = `staff-e2e-${STAFF_E2E_SUFFIX}`;
process.env.RESTRICTION_FINGERPRINT_KEY ??=
  'e2e-fingerprint-key-not-a-secret-000000';
// Cloudflare's documented always-pass Turnstile test secret.
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
