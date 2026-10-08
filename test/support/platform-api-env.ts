import 'dotenv/config';
import { randomUUID } from 'node:crypto';

/**
 * Imported before AppModule: ConfigModule validates the environment when AppModule is loaded,
 * so the platform API settings for the e2e run must exist by then.
 */
export const PLATFORM_E2E_SUFFIX = randomUUID().slice(0, 8);
export const PLATFORM_E2E_CLIENT_ID = `manar-fleet-e2e-${PLATFORM_E2E_SUFFIX}`;
export const PLATFORM_E2E_ROLE = `manar-platform-admin-e2e-${PLATFORM_E2E_SUFFIX}`;

process.env.PLATFORM_API_ISSUER = `${process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081'}/realms/master`;
process.env.PLATFORM_API_CLIENT_ID = PLATFORM_E2E_CLIENT_ID;
process.env.PLATFORM_API_ROLE = PLATFORM_E2E_ROLE;
