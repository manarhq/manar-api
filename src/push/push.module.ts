import { Module } from '@nestjs/common';
import { PushService } from './push.service';

/** Web Push sending, providers only (the mTLS app must not expose the console routes). */
@Module({ providers: [PushService], exports: [PushService] })
export class PushModule {}
