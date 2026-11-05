import { Module } from '@nestjs/common';
import { LearningService } from './learning.service';

/** Learning mode (decision 36), providers only; DatabaseModule and AuditModule are global. */
@Module({ providers: [LearningService], exports: [LearningService] })
export class LearningModule {}
