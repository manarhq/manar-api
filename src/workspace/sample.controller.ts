import {
  Controller,
  Delete,
  HttpCode,
  NotFoundException,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { SampleService } from './sample.service';
import { SampleWorkspaceDto } from './workspace.dto';

/** Any signed-in person, in any of their workspaces: the sample belongs to the user, not the tenant. */
@ApiTags('workspace')
@ApiBearerAuth('jwt')
@Controller('workspace/sample')
@UseGuards(JwtAuthGuard)
export class SampleController {
  constructor(private readonly sample: SampleService) {}

  @Post()
  @ApiOperation({
    summary: 'Try with sample data',
    description:
      'Creates (once per user) a separate SAMPLE workspace filled with synthetic devices, tools, approvals and seven days of activity, and returns its id. Idempotent.',
  })
  @ApiResponse({ status: 201, type: SampleWorkspaceDto })
  @ApiResponse({ status: 503, type: ErrorResponseDto })
  create(@CurrentAuth() auth: AuthContext): Promise<SampleWorkspaceDto> {
    return this.sample.ensure(auth.user.keycloakSubject);
  }

  @Delete()
  @HttpCode(204)
  @ApiOperation({ summary: 'Delete the sample workspace' })
  @ApiResponse({ status: 204 })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async remove(@CurrentAuth() auth: AuthContext): Promise<void> {
    if (!(await this.sample.remove(auth.user.keycloakSubject))) {
      throw new NotFoundException('No sample workspace');
    }
  }
}
