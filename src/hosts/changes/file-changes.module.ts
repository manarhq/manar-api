import { Module } from '@nestjs/common';
import { FileChangesService } from './file-changes.service';

@Module({ providers: [FileChangesService], exports: [FileChangesService] })
export class FileChangesModule {}
