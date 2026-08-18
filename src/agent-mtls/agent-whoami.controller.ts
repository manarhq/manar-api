import { Controller, Get, UseGuards } from '@nestjs/common';
import { CurrentAgent } from './agent-context';
import type { AgentContext } from './agent-context';
import { AgentMtlsGuard } from './agent-mtls.guard';

/**
 * `GET /agent/v1/whoami` — a trivial endpoint that proves `AgentMtlsGuard`
 * works end-to-end (mTLS handshake → certificate → resolved agent
 * identity). This is test infrastructure for Phase 4, not scope creep:
 * Phase 5+ adds real endpoints under `/agent/v1/*`; this one exists so the
 * guard has something to protect and verify against today.
 */
@Controller('agent/v1')
export class AgentWhoamiController {
  @Get('whoami')
  @UseGuards(AgentMtlsGuard)
  whoami(@CurrentAgent() agent: AgentContext): AgentContext {
    return agent;
  }
}
