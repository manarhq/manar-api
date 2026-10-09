/**
 * The GitLab action catalog (REST v4, ADR-0011): every call Manar can make
 * on a GitLab project for a coding agent, fixed in code. `GitLabToolAdapter`
 * only executes an action named here, builds the request only from this
 * definition, and validates `params` against the schema here.
 *
 * The target is always the authorized `resource`, never a value in `params`,
 * so the task's resource selectors, the policy's resource patterns and an
 * approval grant all bind to it:
 *
 * - `group/project`           the project (reads, MR list and create, CI variables)
 * - `group/project:<branch>`  one branch (create, commit, delete, protection)
 * - `group/project!<iid>`     one merge request (get, comment, merge)
 *
 * The project in `resource` must equal the tool's configured project, so one
 * registered GitLab tool can never act on another project, whatever the
 * token could reach.
 */

export type GitLabResourceKind = 'project' | 'branch' | 'mr';

export interface GitLabTarget {
  project: string;
  branch?: string;
  iid?: number;
}

export interface GitLabRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Relative to `projects/<encoded project>/`; built from validated values only. */
  path: string;
  query?: Record<string, string>;
  body?: unknown;
}

export interface GitLabActionDef {
  name: string;
  description: string;
  mutating: boolean;
  destructive: boolean;
  riskBaseScore: number;
  resource: GitLabResourceKind;
  inputSchema: Record<string, unknown>;
  build(target: GitLabTarget, params: Record<string, unknown>): GitLabRequest;
  /** Read sent first; a non-empty answer refuses the action before anything changes. */
  precheck?: {
    request(target: GitLabTarget): GitLabRequest;
    refuse(body: unknown): string | undefined;
  };
  /** Sent instead when the main request answers 404 (create-or-update). */
  onNotFound?(
    target: GitLabTarget,
    params: Record<string, unknown>,
  ): GitLabRequest;
  /** Keeps what the agent needs and drops the rest (avatars, user objects, secrets). */
  shape?(body: unknown): unknown;
}

/** `group[/subgroup]/project`; each segment starts with an alphanumeric, so no `.`/`..`. */
export const GITLAB_PROJECT =
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}(\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}){1,4}$/;
/** A conservative subset of git's ref rules: no `refs/` prefix, `..`, `//`, `@{`, trailing `/` or `.lock`. */
export const GITLAB_BRANCH =
  /^(?!refs\/)(?!.*(?:\.\.|\/\/|@\{|\.lock$|\/$))[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;
const IID = /^[1-9][0-9]{0,9}$/;

/** Splits a resource into its target, or `undefined` if it is not of `kind`. */
export function parseGitLabResource(
  kind: GitLabResourceKind,
  resource: string,
): GitLabTarget | undefined {
  if (kind === 'project') {
    return GITLAB_PROJECT.test(resource) ? { project: resource } : undefined;
  }
  const sep = kind === 'branch' ? ':' : '!';
  const at = resource.indexOf(sep);
  if (at < 0) return undefined;
  const project = resource.slice(0, at);
  const rest = resource.slice(at + 1);
  if (!GITLAB_PROJECT.test(project)) return undefined;
  if (kind === 'branch') {
    return GITLAB_BRANCH.test(rest) ? { project, branch: rest } : undefined;
  }
  return IID.test(rest) ? { project, iid: Number(rest) } : undefined;
}

const seg = encodeURIComponent;
const pick = (o: unknown, keys: string[]): Record<string, unknown> => {
  const src = (o ?? {}) as Record<string, unknown>;
  return Object.fromEntries(
    keys.filter((k) => k in src).map((k) => [k, src[k]]),
  );
};
const username = (o: unknown) =>
  ((o ?? {}) as { author?: { username?: unknown } }).author?.username;

const MR_FIELDS = [
  'iid',
  'title',
  'description',
  'state',
  'source_branch',
  'target_branch',
  'sha',
  'merge_commit_sha',
  'detailed_merge_status',
  'has_conflicts',
  'draft',
  'web_url',
  'created_at',
  'updated_at',
  'merged_at',
];
const shapeMr = (o: unknown) => ({
  ...pick(o, MR_FIELDS),
  author: username(o),
});
const shapeBranch = (o: unknown) => ({
  ...pick(o, ['name', 'protected', 'default', 'merged', 'web_url']),
  commit: pick((o as { commit?: unknown } | null)?.commit, [
    'short_id',
    'title',
  ]),
});
const shapeProtection = (o: unknown) => {
  const levels = (v: unknown) =>
    Array.isArray(v)
      ? v.map(
          (l) =>
            (l as { access_level_description?: unknown })
              .access_level_description,
        )
      : [];
  const src = (o ?? {}) as Record<string, unknown>;
  return {
    name: src.name,
    push: levels(src.push_access_levels),
    merge: levels(src.merge_access_levels),
    allow_force_push: src.allow_force_push,
  };
};

const noParams = { type: 'object', additionalProperties: false };
const branchName = { type: 'string', pattern: GITLAB_BRANCH.source };
/** GitLab access levels: 0 no one, 30 developers, 40 maintainers. */
const accessLevel = { enum: [0, 30, 40] };
/** A repository-relative path: no leading `/`, no `..` segment, no control characters. */
const READ_PATH = '^(?!/)(?!(?:.*/)?\\.\\.(?:/|$))[^\\u0000-\\u001f]{1,500}$';
/** Same, minus CI configuration: an agent's commit could otherwise run code with the project's CI secrets. */
const WRITE_PATH =
  '^(?!\\.gitlab-ci\\.yml$)(?!\\.gitlab/)(?!/)(?!(?:.*/)?\\.\\.(?:/|$))[^\\u0000-\\u001f]{1,500}$';

export const GITLAB_ACTIONS: readonly GitLabActionDef[] = [
  // ---- reads ----
  {
    name: 'gitlab.repo.file.get',
    description:
      'Read one file at a branch, tag or commit (resource: the project). Returns the text content.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    resource: 'project',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['path'],
      properties: {
        path: { type: 'string', pattern: READ_PATH },
        ref: { type: 'string', minLength: 1, maxLength: 200 },
      },
    },
    build: (_t, p) => ({
      method: 'GET',
      path: `repository/files/${seg(String(p.path))}`,
      query: { ref: typeof p.ref === 'string' ? p.ref : 'HEAD' },
    }),
    shape: (o) => {
      const src = (o ?? {}) as Record<string, unknown>;
      return {
        ...pick(o, ['file_path', 'ref', 'size', 'last_commit_id']),
        content:
          typeof src.content === 'string' && src.encoding === 'base64'
            ? Buffer.from(src.content, 'base64').toString('utf8')
            : src.content,
      };
    },
  },
  {
    name: 'gitlab.repo.tree.list',
    description:
      'List files and folders in the repository (resource: the project), optionally under a path and recursively.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    resource: 'project',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', maxLength: 500 },
        ref: { type: 'string', minLength: 1, maxLength: 200 },
        recursive: { type: 'boolean' },
      },
    },
    build: (_t, p) => ({
      method: 'GET',
      path: 'repository/tree',
      query: {
        per_page: '100',
        ...(typeof p.path === 'string' ? { path: p.path } : {}),
        ...(typeof p.ref === 'string' ? { ref: p.ref } : {}),
        ...(p.recursive ? { recursive: 'true' } : {}),
      },
    }),
    shape: (o) =>
      Array.isArray(o) ? o.map((e) => pick(e, ['path', 'type'])) : o,
  },
  {
    name: 'gitlab.mr.list',
    description: 'List merge requests in the project (resource: the project).',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    resource: 'project',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: { state: { enum: ['opened', 'merged', 'closed', 'all'] } },
    },
    build: (_t, p) => ({
      method: 'GET',
      path: 'merge_requests',
      query: {
        state: typeof p.state === 'string' ? p.state : 'opened',
        per_page: '20',
      },
    }),
    shape: (o) => (Array.isArray(o) ? o.map(shapeMr) : o),
  },
  {
    name: 'gitlab.mr.get',
    description:
      'Read one merge request (resource: group/project!iid): branches, state, head commit, merge status.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    resource: 'mr',
    inputSchema: noParams,
    build: (t) => ({ method: 'GET', path: `merge_requests/${t.iid}` }),
    shape: shapeMr,
  },
  {
    name: 'gitlab.pipeline.status',
    description:
      'Latest CI pipelines (resource: the project), optionally for one branch or tag.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    resource: 'project',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: { ref: { type: 'string', minLength: 1, maxLength: 200 } },
    },
    build: (_t, p) => ({
      method: 'GET',
      path: 'pipelines',
      query: {
        per_page: '5',
        ...(typeof p.ref === 'string' ? { ref: p.ref } : {}),
      },
    }),
    shape: (o) =>
      Array.isArray(o)
        ? o.map((e) =>
            pick(e, ['id', 'status', 'ref', 'sha', 'web_url', 'created_at']),
          )
        : o,
  },

  // ---- changes ----
  {
    name: 'gitlab.branch.create',
    description:
      'Create a branch (resource: group/project:<new branch>) from an existing branch, tag or commit.',
    mutating: true,
    destructive: false,
    riskBaseScore: 10,
    resource: 'branch',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['ref'],
      properties: { ref: { type: 'string', minLength: 1, maxLength: 200 } },
    },
    build: (t, p) => ({
      method: 'POST',
      path: 'repository/branches',
      query: { branch: t.branch!, ref: String(p.ref) },
    }),
    shape: shapeBranch,
  },
  {
    name: 'gitlab.commit.create',
    description:
      'Commit file changes to an existing, unprotected branch (resource: group/project:<branch>). Refused on a protected branch and for CI configuration files (.gitlab-ci.yml, .gitlab/).',
    mutating: true,
    destructive: false,
    riskBaseScore: 15,
    resource: 'branch',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['message', 'actions'],
      properties: {
        message: { type: 'string', minLength: 1, maxLength: 2000 },
        actions: {
          type: 'array',
          minItems: 1,
          maxItems: 20,
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['action', 'file_path'],
            properties: {
              action: { enum: ['create', 'update', 'delete'] },
              file_path: { type: 'string', pattern: WRITE_PATH },
              content: { type: 'string', maxLength: 200_000 },
            },
          },
        },
      },
    },
    precheck: {
      request: (t) => ({
        method: 'GET',
        path: `repository/branches/${seg(t.branch!)}`,
      }),
      refuse: (body) =>
        (body as { protected?: unknown } | null)?.protected === false
          ? undefined
          : 'protected_branch',
    },
    build: (t, p) => ({
      method: 'POST',
      path: 'repository/commits',
      body: {
        branch: t.branch,
        commit_message: p.message,
        actions: p.actions,
      },
    }),
    shape: (o) => pick(o, ['id', 'short_id', 'title', 'web_url']),
  },
  {
    name: 'gitlab.mr.create',
    description:
      'Open a merge request (resource: the project) from a source branch into a target branch.',
    mutating: true,
    destructive: false,
    riskBaseScore: 10,
    resource: 'project',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['sourceBranch', 'targetBranch', 'title'],
      properties: {
        sourceBranch: branchName,
        targetBranch: branchName,
        title: { type: 'string', minLength: 1, maxLength: 255 },
        description: { type: 'string', maxLength: 10_000 },
      },
    },
    build: (_t, p) => ({
      method: 'POST',
      path: 'merge_requests',
      body: {
        source_branch: p.sourceBranch,
        target_branch: p.targetBranch,
        title: p.title,
        ...(typeof p.description === 'string'
          ? { description: p.description }
          : {}),
        remove_source_branch: false,
      },
    }),
    shape: shapeMr,
  },
  {
    name: 'gitlab.mr.comment',
    description:
      'Add a comment to a merge request (resource: group/project!iid).',
    mutating: true,
    destructive: false,
    riskBaseScore: 5,
    resource: 'mr',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['body'],
      properties: { body: { type: 'string', minLength: 1, maxLength: 10_000 } },
    },
    build: (t, p) => ({
      method: 'POST',
      path: `merge_requests/${t.iid}/notes`,
      body: { body: p.body },
    }),
    shape: (o) => pick(o, ['id', 'body', 'created_at']),
  },

  // ---- risky ----
  {
    name: 'gitlab.mr.merge',
    description:
      'Merge a merge request into its target branch (resource: group/project!iid). Pass `sha` (from gitlab.mr.get) to merge only that exact head commit.',
    mutating: true,
    destructive: false,
    riskBaseScore: 30,
    resource: 'mr',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        sha: { type: 'string', pattern: '^[0-9a-f]{40}$' },
        squash: { type: 'boolean' },
      },
    },
    build: (t, p) => ({
      method: 'PUT',
      path: `merge_requests/${t.iid}/merge`,
      body: {
        ...(typeof p.sha === 'string' ? { sha: p.sha } : {}),
        ...(typeof p.squash === 'boolean' ? { squash: p.squash } : {}),
        should_remove_source_branch: false,
      },
    }),
    shape: shapeMr,
  },
  {
    name: 'gitlab.branch.delete',
    description:
      'Delete a branch (resource: group/project:<branch>). Commits only on that branch become unreachable.',
    mutating: true,
    destructive: true,
    riskBaseScore: 25,
    resource: 'branch',
    inputSchema: noParams,
    build: (t) => ({
      method: 'DELETE',
      path: `repository/branches/${seg(t.branch!)}`,
    }),
  },
  {
    name: 'gitlab.branch.protection.change',
    description:
      'Protect a branch with the given push and merge levels, or remove its protection (resource: group/project:<branch>). Removing protection lets anyone with push rights rewrite it.',
    mutating: true,
    destructive: true,
    riskBaseScore: 40,
    resource: 'branch',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['protect'],
      properties: {
        protect: { type: 'boolean' },
        pushAccessLevel: accessLevel,
        mergeAccessLevel: accessLevel,
      },
    },
    build: (t, p) =>
      p.protect
        ? {
            method: 'POST',
            path: 'protected_branches',
            body: {
              name: t.branch,
              push_access_level: p.pushAccessLevel ?? 0,
              merge_access_level: p.mergeAccessLevel ?? 40,
              allow_force_push: false,
            },
          }
        : { method: 'DELETE', path: `protected_branches/${seg(t.branch!)}` },
    shape: shapeProtection,
  },
  {
    name: 'gitlab.project.variable.set',
    description:
      'Create or update a project CI/CD variable (resource: the project). Pipelines can read it, so it can expose or change what CI runs with. The value is never returned.',
    mutating: true,
    destructive: false,
    riskBaseScore: 40,
    resource: 'project',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['key', 'value'],
      properties: {
        key: { type: 'string', pattern: '^[A-Za-z_][A-Za-z0-9_]{0,254}$' },
        value: { type: 'string', maxLength: 10_000 },
        protected: { type: 'boolean' },
        masked: { type: 'boolean' },
      },
    },
    build: (_t, p) => ({
      method: 'PUT',
      path: `variables/${seg(String(p.key))}`,
      body: variableBody(p),
    }),
    onNotFound: (_t, p) => ({
      method: 'POST',
      path: 'variables',
      body: { key: p.key, ...variableBody(p) },
    }),
    shape: (o) => pick(o, ['key', 'protected', 'masked', 'variable_type']),
  },
];

function variableBody(p: Record<string, unknown>) {
  return {
    value: p.value,
    protected: p.protected ?? true,
    masked: p.masked ?? true,
  };
}

const BY_NAME = new Map(GITLAB_ACTIONS.map((a) => [a.name, a]));

export function findGitLabAction(name: string): GitLabActionDef | undefined {
  return BY_NAME.get(name);
}
