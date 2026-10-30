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
