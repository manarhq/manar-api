import { Module } from '@nestjs/common';
import { CatalogController } from './catalog.controller';
import { CatalogService } from './catalog.service';
import { CatalogUsageStore } from './catalog.usage';
import { PlatformAuthGuard } from './platform-auth.guard';

/** The catalog gate, for every module that enforces it (decision path, LLM proxy, assistant). */
@Module({
  providers: [CatalogService, CatalogUsageStore],
  exports: [CatalogService],
})
export class CatalogModule {}

/** The fleet-facing catalog API. Imported only into AppModule (human HTTP app). */
@Module({
  imports: [CatalogModule],
  controllers: [CatalogController],
  providers: [PlatformAuthGuard],
})
export class CatalogHttpModule {}
