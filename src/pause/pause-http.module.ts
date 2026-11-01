import { Module } from '@nestjs/common';
import { PauseController } from './pause.controller';
import { PauseModule } from './pause.module';

/** The console HTTP surface. Imported only into `AppModule`. */
@Module({ imports: [PauseModule], controllers: [PauseController] })
export class PauseHttpModule {}
