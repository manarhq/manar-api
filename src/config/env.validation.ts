import { z } from 'zod';
import { DatabaseConfigSchema } from '../database/database.config';
import { KeycloakConfigSchema } from '../keycloak/keycloak.config';
import { OpenBaoConfigSchema } from '../openbao/openbao.config';
import { AgentMtlsConfigSchema } from '../agent-mtls/agent-mtls.config';
import { OpenFgaConfigSchema } from '../authorization/openfga.config';
import { TemporalConfigSchema } from '../temporal/temporal.config';
import { ApprovalsConfigSchema } from '../approvals/approvals.config';
import { KafkaConfigSchema } from '../audit/kafka.config';
import { OpenSearchConfigSchema } from '../audit/opensearch/opensearch.config';
import { RedisConfigSchema } from '../audit/live/redis.config';
import { AiAdvisoryConfigSchema } from '../ai-advisory/ai-advisory.config';
import { KillSwitchesConfigSchema } from '../kill-switches/kill-switches.config';
import { RateLimitConfigSchema } from '../rate-limit/rate-limit.config';
import { SecurityConfigSchema } from '../security/security.config';
import { WebhooksConfigSchema } from '../webhooks/webhooks.config';
import { IdempotencyConfigSchema } from '../idempotency/idempotency.config';
import { SsrfConfigSchema } from '../common/ssrf/ssrf.config';
import { TenantsConfigSchema } from '../tenants/tenants.config';
import { LlmProxyConfigSchema } from '../agent-runtime/llm-proxy.config';

/**
 * Application-level environment schema.
 *
 * Keep this schema scoped to the config every module in this phase actually
 * needs (PORT, NODE_ENV, LOG_LEVEL). Later phases that introduce their own
 * modules (database, auth, etc.) should add their own schema alongside that
 * module rather than growing this one into a god-schema — see
 * `src/database/database.config.ts`'s `DatabaseConfigSchema` and
 * `src/keycloak/keycloak.config.ts`'s `KeycloakConfigSchema`, merged in
 * below. `@nestjs/config`'s `validate()` extension point only accepts a
 * single function, so the merge happens here while each schema's fields
 * stay defined next to the module that owns them.
 */
export const AppConfigSchema = z
  .object({
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    NODE_ENV: z
      .enum(['development', 'production', 'test'])
      .default('development'),
    LOG_LEVEL: z
      .enum(['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'])
      .default('info'),
  })
  .extend(DatabaseConfigSchema.shape)
  .extend(KeycloakConfigSchema.shape)
  .extend(OpenBaoConfigSchema.shape)
  .extend(AgentMtlsConfigSchema.shape)
  .extend(OpenFgaConfigSchema.shape)
  .extend(TemporalConfigSchema.shape)
  .extend(ApprovalsConfigSchema.shape)
  .extend(KafkaConfigSchema.shape)
  .extend(OpenSearchConfigSchema.shape)
  .extend(RedisConfigSchema.shape)
  .extend(AiAdvisoryConfigSchema.shape)
  .extend(KillSwitchesConfigSchema.shape)
  .extend(RateLimitConfigSchema.shape)
  .extend(SecurityConfigSchema.shape)
  .extend(WebhooksConfigSchema.shape)
  .extend(IdempotencyConfigSchema.shape)
  .extend(SsrfConfigSchema.shape)
  .extend(TenantsConfigSchema.shape)
  .extend(LlmProxyConfigSchema.shape);

export type AppConfig = z.infer<typeof AppConfigSchema>;

/**
 * Custom `validate()` function for `ConfigModule.forRoot()` (the
 * NestJS-documented extension point for plugging in a validation library
 * other than the built-in Joi option). Runs once at startup; throws with a
 * readable, itemized error message if any variable is missing or invalid so
 * the process fails fast instead of booting into a bad state.
 */
export function validate(config: Record<string, unknown>): AppConfig {
  const result = AppConfigSchema.safeParse(config);

  if (!result.success) {
    const issues = result.error.issues
      .map(
        (issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`,
      )
      .join('\n');

    throw new Error(
      `Invalid environment configuration. Fix the following and restart:\n${issues}`,
    );
  }

  return result.data;
}
