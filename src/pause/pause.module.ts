import { Module } from '@nestjs/common';
import { PauseService } from './pause.service';

/** Providers only (the worker and the mTLS listener import this one). */
@Module({ providers: [PauseService], exports: [PauseService] })
export class PauseModule {}
