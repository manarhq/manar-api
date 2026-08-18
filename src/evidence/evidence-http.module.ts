import { Module } from '@nestjs/common';
import { EvidenceExportService } from './evidence-export.service';
import { EvidenceController } from './evidence.controller';

/** The human-facing `/evidence` HTTP surface (Section 49). Imported only into `AppModule`. */
@Module({
  providers: [EvidenceExportService],
  controllers: [EvidenceController],
})
export class EvidenceHttpModule {}
