import { Module } from '@nestjs/common';
import { EdgeModule } from './edge.module';
import {
  EdgeGatewayGuard,
  EdgeInternalController,
} from './edge-internal.controller';
import { EgressRulesController } from './egress-rules.controller';

/**
 * The gateway sync API and the egress allow-list API. Imported only into `AppModule` (the HTTP
 * port), never into `AgentMtlsAppModule`: `/internal/*` must not exist on the agent listener.
 */
@Module({
  imports: [EdgeModule],
  controllers: [EdgeInternalController, EgressRulesController],
  providers: [EdgeGatewayGuard],
})
export class EdgeHttpModule {}
