import { readFileSync } from 'node:fs';
import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { ConfigService } from '@nestjs/config';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { AppModule } from './app.module';
import { AgentMtlsAppModule } from './agent-mtls/agent-mtls-app.module';
import { validate } from './config/env.validation';
import type { AppConfig } from './config/env.validation';
import { setupOpenApiDocs } from './openapi/setup-openapi-docs';
import { setupCors, setupHelmet } from './security/setup-security';

async function bootstrap(): Promise<void> {
  // Validated once, directly against process.env, before either Nest
  // application exists — the mTLS listener's https options
  // (cert/key/ca/requestCert) must be resolved at FastifyAdapter
  // *construction* time, before Nest's DI container (and therefore
  // ConfigService) is available. Same bootstrap-time constraint
  // agent-mtls.config.ts's doc comment describes.
  const bootstrapConfig = validate(process.env);

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
    { bufferLogs: true },
  );
  app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));

  const configService = app.get(ConfigService<AppConfig, true>);
  const port = configService.get('PORT', { infer: true });
  setupHelmet(app);
  setupCors(app, configService);
  setupOpenApiDocs(app, configService);
  await app.listen(port, '0.0.0.0');

  const agentMtlsApp = await NestFactory.create<NestFastifyApplication>(
    AgentMtlsAppModule,
    new FastifyAdapter({
      https: {
        cert: readFileSync(bootstrapConfig.AGENT_MTLS_SERVER_CERT_PATH),
        key: readFileSync(bootstrapConfig.AGENT_MTLS_SERVER_KEY_PATH),
        // The trust anchor for CLIENT certificates (mutual TLS) — the
        // FULL chain (intermediate + root, see agent-mtls.config.ts's doc
        // comment for why not the intermediate alone). Node's TLS layer
        // refuses the handshake outright for a client cert that doesn't
        // chain to this, before AgentMtlsGuard (defense in depth beyond
        // that) ever runs.
        ca: readFileSync(bootstrapConfig.AGENT_MTLS_CLIENT_CA_PATH),
        requestCert: true,
        rejectUnauthorized: true,
      },
    }),
    { bufferLogs: true },
  );
  agentMtlsApp.useLogger(agentMtlsApp.get(WINSTON_MODULE_NEST_PROVIDER));
  setupHelmet(agentMtlsApp);
  await agentMtlsApp.listen(bootstrapConfig.AGENT_MTLS_PORT, '0.0.0.0');
}

void bootstrap();
