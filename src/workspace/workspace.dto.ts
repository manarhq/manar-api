import { ApiProperty } from '@nestjs/swagger';
import { START_MODES } from './start-mode.presets';

export class StartModeResponseDto {
  @ApiProperty({ enum: [...START_MODES, 'custom'] })
  mode!: string;
}

export class SetStartModeRequestDto {
  @ApiProperty({ enum: START_MODES })
  mode!: string;
}

export class ReportCardDto {
  @ApiProperty() from!: string;
  @ApiProperty() to!: string;
  @ApiProperty() actions!: number;
  @ApiProperty() askedYou!: number;
  @ApiProperty() blocked!: number;
  @ApiProperty() secretsKeptSafe!: number;
  @ApiProperty({ type: [Number] }) series!: number[];
}

export class ReportShareCreatedDto {
  @ApiProperty() shareId!: string;
  @ApiProperty() createdAt!: Date;
}

export class ReportShareRowDto {
  @ApiProperty() id!: string;
  @ApiProperty() createdAt!: Date;
  @ApiProperty({ nullable: true, type: Date }) revokedAt!: Date | null;
}
