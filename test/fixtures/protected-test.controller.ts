import { Controller, Get, UseGuards } from '@nestjs/common';
import { CurrentAuth } from '../../src/auth/auth-context';
import type { AuthContext } from '../../src/auth/auth-context';
import { JwtAuthGuard } from '../../src/auth/jwt-auth.guard';
import { RequireRole } from '../../src/auth/require-role.decorator';
import { RolesGuard } from '../../src/auth/roles.guard';

/**
 * Test-only controller used solely by test/auth.e2e-spec.ts to exercise
 * JwtAuthGuard/RolesGuard/@CurrentAuth() against a real running HTTP
 * server, since Phase 3 ships no real protected domain endpoints yet
 * (no SOC UI/API this phase — see the design spec's "Out of scope").
 */
@Controller('__test-protected')
export class ProtectedTestController {
  @Get('any-authenticated-user')
  @UseGuards(JwtAuthGuard)
  anyAuthenticatedUser(@CurrentAuth() auth: AuthContext): AuthContext {
    return auth;
  }

  @Get('security-admin-only')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRole('SECURITY_ADMIN')
  securityAdminOnly(@CurrentAuth() auth: AuthContext): AuthContext {
    return auth;
  }
}
