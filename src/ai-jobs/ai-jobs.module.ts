import { Module } from '@nestjs/common';
import { AiJobStore } from './ai-job.store';

@Module({ providers: [AiJobStore], exports: [AiJobStore] })
export class AiJobsModule {}
