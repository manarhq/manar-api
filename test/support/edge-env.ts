import 'dotenv/config';
import { randomBytes } from 'node:crypto';

/**
 * Imported before AppModule (ConfigModule validates the environment when AppModule loads): turns
 * the edge on for test/edge.e2e-spec.ts with throwaway values. Nothing here is a real secret.
 */
export const EDGE_E2E_GATEWAY_TOKEN = randomBytes(32).toString('hex');
export const EDGE_E2E_GATEWAY_KEY = randomBytes(32).toString('base64');

process.env.MANAR_EDGE_ENABLED = 'true';
process.env.MANAR_EDGE_CIDR = '100.88.0.0/16';
process.env.MANAR_EDGE_ENDPOINT = 'edge.example.test:51820';
process.env.MANAR_EDGE_GATEWAY_PUBLIC_KEY = EDGE_E2E_GATEWAY_KEY;
process.env.MANAR_EDGE_GATEWAY_TOKEN = EDGE_E2E_GATEWAY_TOKEN;
process.env.MANAR_AGENTS_HOST = 'agents.example.test';
