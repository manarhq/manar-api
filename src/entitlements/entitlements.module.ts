import { Module } from '@nestjs/common';
import { EntitlementsService } from './entitlements.service';

/** Local stub, see `entitlements.service.ts`. */
@Module({ providers: [EntitlementsService], exports: [EntitlementsService] })
export class EntitlementsModule {}
