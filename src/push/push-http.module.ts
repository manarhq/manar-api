import { Module } from '@nestjs/common';
import { PushController } from './push.controller';
import { PushModule } from './push.module';

/** `/push/*` for the console. Imported only into `AppModule`. */
@Module({ imports: [PushModule], controllers: [PushController] })
export class PushHttpModule {}
