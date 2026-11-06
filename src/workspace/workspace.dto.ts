import { ApiProperty } from '@nestjs/swagger';
import { START_MODES } from './start-mode.presets';

export class LearningSettingDto {
  @ApiProperty({
    description: 'New devices are watched, not asked, for `days`',
  })
  enabled!: boolean;
  @ApiProperty() days!: number;
  @ApiProperty({
    enum: ['default', 'workspace'],
    description:
      'default: on, except Government and sample workspaces; workspace: an admin chose',
  })
  source!: string;
}

export class StartModeResponseDto {
  @ApiProperty({ enum: [...START_MODES, 'custom'] })
  mode!: string;
  @ApiProperty({ type: LearningSettingDto })
  learning!: LearningSettingDto;
}

export class SetStartModeRequestDto {
  @ApiProperty({ enum: START_MODES, required: false })
  mode?: string;
  @ApiProperty({ enum: ['on', 'off', 'default'], required: false })
  learning?: string;
}

export class ReportCardDto {
  @ApiProperty() from!: string;
  @ApiProperty() to!: string;
  @ApiProperty() actions!: number;
  @ApiProperty() askedYou!: number;
  @ApiProperty() blocked!: number;
  @ApiProperty() secretsKeptSafe!: number;
  @ApiProperty({ type: [Number] }) series!: number[];
  @ApiProperty({
    required: false,
    type: Object,
    description:
      'Present when the link shares one agent session: tool, duration, counts and steps with programs, extensions and hosts only.',
  })
  session?: object;
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

export class SampleWorkspaceDto {
  @ApiProperty() tenantId!: string;
  @ApiProperty({ enum: ['ACTIVE', 'QUEUED'] }) status!: string;
}
