import { buildApp } from './app';
import { validate } from './config/env';

async function bootstrap(): Promise<void> {
  const config = validate(process.env);

  const app = buildApp({
    apiKey: config.DEMO_TOOLS_API_KEY,
    logger: { level: config.LOG_LEVEL },
  });

  await app.listen({ port: config.PORT, host: '0.0.0.0' });
}

void bootstrap();
