import { Module } from '@nestjs/common';
import { ProtectedTestController } from './protected-test.controller';

/**
 * Mounted alongside `AppModule` only in test/auth.e2e-spec.ts. JwtAuthGuard
 * and RolesGuard are resolved from `AuthModule` (Global, already loaded by
 * AppModule) — this module only needs to declare the controller.
 */
@Module({
  controllers: [ProtectedTestController],
})
export class ProtectedTestModule {}
