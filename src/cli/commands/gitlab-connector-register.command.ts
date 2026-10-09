import { Logger } from '@nestjs/common';
import { Command, CommandRunner, Option } from 'nest-commander';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../../generated/tenant-client/client';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { GITLAB_ACTIONS, GITLAB_PROJECT } from '../../tools/gitlab-actions';

export interface GitLabToolInput {
  /** Tool name agents and policies use, e.g. `gitlab-demo`. */
  name: string;
  /** The instance's REST base, e.g. `https://gitlab.example.com/api/v4`. */
  baseEndpoint: string;
  /** The one project this tool may act on, e.g. `manar/demo-repo`. */
  project: string;
  /** OpenBao KV path holding the project access token as `{ value }`. */
  kvPath: string;
  /** `LIVE` for a real GitLab instance, `DEMO_FIXTURE` for a stand-in. */
  dataOrigin: 'LIVE' | 'DEMO_FIXTURE';
}

/**
 * ADR-0011: registers one GitLab tool (one project) and the catalog actions
 * in a tenant. Idempotent. Rows are written from the code catalog so policy,
 * risk and the tool manifest see the same flags the adapter uses.
 */
export async function ensureGitLabTool(
  tenantClient: TenantPrismaClient,
  input: GitLabToolInput,
): Promise<{ id: string; name: string }> {
  if (!GITLAB_PROJECT.test(input.project)) {
    throw new Error(`Invalid GitLab project path "${input.project}"`);
  }
  const data = {
    type: 'SCM',
    vendor: 'GitLab',
    description: `GitLab connector for project ${input.project} only (REST v4, project access token held by Manar).`,
    baseEndpoint: input.baseEndpoint,
    protocol: 'GITLAB' as const,
    credentialReference: { provider: 'OPENBAO', reference: input.kvPath },
    metadata: { project: input.project, dataOrigin: input.dataOrigin },
  };
  const tool = await tenantClient.tool.upsert({
    where: { name: input.name },
    create: { name: input.name, ...data },
    update: data,
  });
  for (const action of GITLAB_ACTIONS) {
    const row = {
      description: action.description,
      riskBaseScore: action.riskBaseScore,
      mutating: action.mutating,
      destructive: action.destructive,
      inputSchema: action.inputSchema as Prisma.InputJsonObject,
    };
    await tenantClient.toolAction.upsert({
      where: { toolId_name: { toolId: tool.id, name: action.name } },
      create: { toolId: tool.id, name: action.name, ...row },
      update: row,
    });
  }
  return { id: tool.id, name: tool.name };
}

/**
 * The coding pack's default policy for one GitLab tool (first match wins):
 * a direct change to a protected branch is refused; protection changes and
 * CI variables need a person and score high risk; merges and branch
 * deletes need a person; reads, branches, commits, merge requests and
 * comments inside the project are allowed (the task's execution budget caps
 * how many); anything else on this tool, any other project included, is
 * refused.
 */
export function gitlabPolicyContent(
  toolId: string,
  project: string,
  protectedBranches: readonly string[] = ['main'],
) {
  const P = project;
  const rule = (
    name: string,
    actionId: string,
    resourcePattern: string,
    effect: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED',
    extra: { riskWeight?: number; riskFloor?: number } = {},
  ) => ({ name, toolId, actionId, resourcePattern, effect, ...extra });
  return {
    rules: [
      ...protectedBranches.flatMap((b) => [
        rule(
          `No direct commit to protected ${b}`,
          'gitlab.commit.create',
          `${P}:${b}`,
          'DENY',
        ),
        rule(
          `Protected ${b} is never deleted`,
          'gitlab.branch.delete',
          `${P}:${b}`,
          'DENY',
        ),
        rule(
          `Protected ${b} is never recreated`,
          'gitlab.branch.create',
          `${P}:${b}`,
          'DENY',
        ),
      ]),
      rule(
        'Branch protection change needs a person (high risk)',
        'gitlab.branch.protection.change',
        `${P}:*`,
        'APPROVAL_REQUIRED',
        { riskFloor: 85 },
      ),
      rule(
        'CI variable change needs a person (high risk)',
        'gitlab.project.variable.set',
        P,
        'APPROVAL_REQUIRED',
        { riskFloor: 85 },
      ),
      rule(
        'Merge needs a person',
        'gitlab.mr.merge',
        `${P}!*`,
        'APPROVAL_REQUIRED',
        { riskWeight: 20 },
      ),
      rule(
        'Branch delete needs a person',
        'gitlab.branch.delete',
        `${P}:*`,
        'APPROVAL_REQUIRED',
        { riskWeight: 20 },
      ),
      ...[
        'gitlab.repo.file.get',
        'gitlab.repo.tree.list',
        'gitlab.mr.list',
        'gitlab.pipeline.status',
      ].map((a) => rule(`${a} is a read`, a, P, 'ALLOW')),
      rule('gitlab.mr.get is a read', 'gitlab.mr.get', `${P}!*`, 'ALLOW'),
      rule('Create a branch', 'gitlab.branch.create', `${P}:*`, 'ALLOW'),
      rule(
        'Commit to an unprotected branch',
        'gitlab.commit.create',
        `${P}:*`,
        'ALLOW',
      ),
      rule('Open a merge request', 'gitlab.mr.create', P, 'ALLOW'),
      rule(
        'Comment on a merge request',
        'gitlab.mr.comment',
        `${P}!*`,
        'ALLOW',
      ),
      rule(`Nothing outside ${P}`, '*', '*', 'DENY'),
    ],
  };
}

/** Every catalog action on this tool, any resource: the policy above narrows it to the project. */
export function codingTaskGrants(toolId: string) {
  return {
    allowedToolActions: GITLAB_ACTIONS.map((a) => ({
      toolId,
      actionId: a.name,
    })),
    allowedResourceSelectors: [{ toolId, pattern: '*' }],
    forbiddenActions: [],
  };
}

@Command({
  name: 'gitlab:register',
  description:
    'Register a GitLab connector tool for one project in one tenant (the token must already be in OpenBao)',
})
export class GitLabConnectorRegisterCommand extends CommandRunner {
  private readonly logger = new Logger(GitLabConnectorRegisterCommand.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {
    super();
  }

  async run(
    _args: string[],
    options: {
      tenant: string;
      name: string;
      baseUrl: string;
      project: string;
      kvPath: string;
      fixture?: boolean;
    },
  ): Promise<void> {
    const tenant = await this.control.tenant.findUnique({
      where: { slug: options.tenant },
    });
    if (!tenant) throw new Error(`Tenant "${options.tenant}" not found`);
    const tool = await ensureGitLabTool(
      await this.tenantDatabaseManager.getClient(tenant.id),
      {
        name: options.name,
        baseEndpoint: options.baseUrl,
        project: options.project,
        kvPath: options.kvPath,
        dataOrigin: options.fixture ? 'DEMO_FIXTURE' : 'LIVE',
      },
    );
    this.logger.log(
      `Registered tool "${tool.name}" (id=${tool.id}) for ${options.project}`,
    );
    process.exitCode = 0;
  }

  @Option({
    flags: '--tenant <slug>',
    description: 'Tenant slug',
    required: true,
  })
  parseTenant(value: string): string {
    return value;
  }

  @Option({ flags: '--name <tool>', description: 'Tool name', required: true })
  parseName(value: string): string {
    return value;
  }

  @Option({
    flags: '--base-url <url>',
    description: 'GitLab REST base, e.g. https://gitlab.example.com/api/v4',
    required: true,
  })
  parseBaseUrl(value: string): string {
    return value;
  }

  @Option({
    flags: '--project <path>',
    description: 'group/project',
    required: true,
  })
  parseProject(value: string): string {
    return value;
  }

  @Option({
    flags: '--kv-path <path>',
    description: 'OpenBao KV path of the token, e.g. tools/gitlab-demo',
    required: true,
  })
  parseKvPath(value: string): string {
    return value;
  }

  @Option({
    flags: '--fixture',
    description: 'Mark the tool as a DEMO FIXTURE',
  })
  parseFixture(): boolean {
    return true;
  }
}
