import { Global, Module } from '@nestjs/common';
import { EdgePeerService } from './edge-peer.service';

/**
 * docs/edge.md. Providers only and global, imported by both apps (HTTP and agent mTLS) so every
 * service that changes an agent's stop conditions can call the refresh hooks, including the
 * quarantine path that runs on the mTLS listener. The HTTP surface is `EdgeHttpModule`.
 */
@Global()
@Module({
  providers: [EdgePeerService],
  exports: [EdgePeerService],
})
export class EdgeModule {}
