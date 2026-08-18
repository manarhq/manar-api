import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { validate } from './env.validation';

/**
 * Thin wrapper around `@nestjs/config` that wires in the Zod-backed
 * `validate()` function. Imported once, globally, from `AppModule`.
 *
 * This is the only place in the codebase allowed to read `process.env`
 * indirectly (via `@nestjs/config`'s own `.env` loading) — every other
 * module must go through `ConfigService`.
 */
@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      validate,
    }),
  ],
})
export class AppConfigModule {}
