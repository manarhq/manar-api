import { randomBytes } from 'node:crypto';
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from 'fastify';

/**
 * DEMO FIXTURE: a small in-memory mimic of the GitLab REST v4 endpoints
 * manar-api's GitLab connector (`src/tools/gitlab-tool.adapter.ts`) calls,
 * for one project. It is not GitLab and proves nothing about a live
 * instance; every JSON object it returns carries `"_dataOrigin": "DEMO_FIXTURE"`.
 *
 * Layout under the mount prefix (`/gitlab` in `app.ts`):
 *   /api/v4/projects/:project/...              catalog routes (PRIVATE-TOKEN)
 *   /_fixture/{reset,state,requests,faults}    test/demo controls, no auth
 */

export const GITLAB_FIXTURE_DEFAULTS = {
  project: 'manar/demo-repo',
  /** Dev-only fixture token; the connector reads it from OpenBao like a real one. */
  token: 'manar-dev-gitlab-fixture-token',
} as const;

export interface GitLabFixtureOptions {
  project?: string;
  token?: string;
}

interface Branch {
  sha: string;
  title: string;
  files: Map<string, string>;
}

interface MergeRequest {
  iid: number;
  title: string;
  description: string;
  state: 'opened' | 'merged' | 'closed';
  source_branch: string;
  target_branch: string;
  merge_commit_sha: string | null;
  notes: { id: number; body: string }[];
}

interface Fault {
  status: number;
  message?: string;
  /** Sent as `Location` (a redirect fault). */
  location?: string;
  remaining: number;
}

const sha = () => randomBytes(20).toString('hex');

class FixtureState {
  branches = new Map<string, Branch>();
  protectedBranches = new Map<string, { push: number; merge: number }>();
  mergeRequests: MergeRequest[] = [];
  variables = new Map<
    string,
    { value: string; protected: boolean; masked: boolean }
  >();
  requests: { method: string; path: string; query: unknown; body: unknown }[] =
    [];
  faults = new Map<string, Fault>();
  nextNote = 1;
  /** Test control: retarget this MR just before its next merge runs (a race a precheck cannot see). */
  retargetOnMerge: { iid: number; targetBranch: string } | null = null;
  /** Test control: report `checking` merge status for this many more reads (GitLab right after a push). */
  checkingReads = 0;

  constructor() {
    this.reset();
  }

  reset(): void {
    const files = new Map([
      ['README.md', '# demo-repo\n\nA small demo project.\n'],
      ['src/greeting.py', 'def greet(name):\n    return f"Hello, {name}!"\n'],
    ]);
    const main = { sha: sha(), title: 'Initial commit', files };
    this.branches = new Map([
      ['main', main],
      ['develop', { ...main, files: new Map(files) }],
    ]);
    this.protectedBranches = new Map([['main', { push: 0, merge: 40 }]]);
    this.mergeRequests = [];
    this.variables.clear();
    this.requests = [];
    this.faults.clear();
    this.nextNote = 1;
    this.retargetOnMerge = null;
    this.checkingReads = 0;
  }
}

const levelName = (l: number) =>
  ({ 0: 'No one', 30: 'Developers + Maintainers', 40: 'Maintainers' })[l] ??
  String(l);

export default function gitlabFixtureRoutes(
  fastify: FastifyInstance,
  opts: GitLabFixtureOptions,
): void {
  const config = { ...GITLAB_FIXTURE_DEFAULTS, ...opts };
  const state = new FixtureState();
  const prefix = fastify.prefix;
  const pathOf = (request: FastifyRequest) =>
    request.url.split('?')[0]!.slice(prefix.length);
  const fail = (reply: FastifyReply, status: number, message: string) =>
    reply.code(status).send({ message });

  fastify.addHook('preSerialization', async (_req, _reply, payload) =>
    payload && typeof payload === 'object' && !Array.isArray(payload)
      ? { ...payload, _dataOrigin: 'DEMO_FIXTURE' }
      : payload,
  );

  fastify.addHook('preHandler', async (request, reply) => {
    const path = pathOf(request);
    if (path.startsWith('/_fixture')) return;
    state.requests.push({
      method: request.method,
      path,
      query: { ...(request.query as Record<string, unknown>) },
      body: request.body ?? null,
    });
    if (request.headers['private-token'] !== config.token) {
      return fail(reply, 401, '401 Unauthorized');
    }
    const key = `${request.method} ${path}`;
    const fault = state.faults.get(key);
    if (fault) {
      fault.remaining -= 1;
      if (fault.remaining <= 0) state.faults.delete(key);
      if (fault.location) reply.header('location', fault.location);
      return fail(reply, fault.status, fault.message ?? 'FixtureInjectedFault');
    }
  });

  // ---- fixture controls ----
  fastify.post('/_fixture/reset', () => {
    state.reset();
    return { status: 'reset' };
  });
  fastify.get('/_fixture/state', () => ({
    branches: Object.fromEntries(
      [...state.branches].map(([name, b]) => [
        name,
        { sha: b.sha, title: b.title, files: Object.fromEntries(b.files) },
      ]),
    ),
    protectedBranches: [...state.protectedBranches.keys()],
    mergeRequests: state.mergeRequests,
    variables: [...state.variables.keys()],
  }));
  fastify.get('/_fixture/requests', () => ({ requests: state.requests }));
  fastify.post('/_fixture/checking', (request) => {
    state.checkingReads = (request.body as { reads: number }).reads;
    return { status: 'armed' };
  });
  fastify.post('/_fixture/retarget-on-merge', (request) => {
    state.retargetOnMerge = request.body as {
      iid: number;
      targetBranch: string;
    };
    return { status: 'armed' };
  });
  fastify.post('/_fixture/faults', (request) => {
    const b = request.body as {
      method: string;
      path: string;
      status: number;
      message?: string;
      location?: string;
      times?: number;
    };
    state.faults.set(`${b.method} ${b.path}`, {
      status: b.status,
      message: b.message,
      location: b.location,
      remaining: b.times ?? 1,
    });
    return { status: 'armed' };
  });

  // ---- GitLab REST v4, one project ----
  fastify.register(
    (api, _o, done) => {
      api.addHook('preHandler', async (request, reply) => {
        if (
          (request.params as { project?: string }).project !== config.project
        ) {
          return fail(reply, 404, '404 Project Not Found');
        }
      });

      const branchView = (name: string) => {
        const b = state.branches.get(name)!;
        return {
          name,
          protected: state.protectedBranches.has(name),
          default: name === 'main',
          merged: false,
          web_url: `https://gitlab.fixture/${config.project}/-/tree/${name}`,
          commit: { id: b.sha, short_id: b.sha.slice(0, 8), title: b.title },
        };
      };
      const mrView = (mr: MergeRequest) => ({
        ...mr,
        notes: undefined,
        sha: state.branches.get(mr.source_branch)?.sha ?? null,
        detailed_merge_status:
          mr.state !== 'opened'
            ? 'not_open'
            : state.checkingReads-- > 0
              ? 'checking'
              : 'mergeable',
        author: {
          username: 'project_bot',
          avatar_url: 'https://gitlab.fixture/a.png',
        },
        web_url: `https://gitlab.fixture/${config.project}/-/merge_requests/${mr.iid}`,
      });
      const mrOf = (request: FastifyRequest) =>
        state.mergeRequests.find(
          (m) => m.iid === Number((request.params as { iid: string }).iid),
        );
      const ref = (q: unknown) => (q as { ref?: string }).ref ?? 'main';
      const branchOf = (name: string) =>
        state.branches.get(name === 'HEAD' ? 'main' : name);

      api.get('/repository/files/:file', (request, reply) => {
        const file = (request.params as { file: string }).file;
        const content = branchOf(ref(request.query))?.files.get(file);
        if (content === undefined)
          return fail(reply, 404, '404 File Not Found');
        return {
          file_path: file,
          ref: ref(request.query),
          size: Buffer.byteLength(content),
          encoding: 'base64',
          content: Buffer.from(content).toString('base64'),
          last_commit_id: branchOf(ref(request.query))!.sha,
        };
      });
      api.get('/repository/tree', (request, reply) => {
        const branch = branchOf(ref(request.query));
        if (!branch) return fail(reply, 404, '404 Tree Not Found');
        return [...branch.files.keys()].map((path) => ({
          path,
          type: 'blob',
          mode: '100644',
        }));
      });
      api.get('/repository/branches/:branch', (request, reply) => {
        const name = (request.params as { branch: string }).branch;
        return state.branches.has(name)
          ? branchView(name)
          : fail(reply, 404, '404 Branch Not Found');
      });
      api.post('/repository/branches', (request, reply) => {
        const q = request.query as { branch: string; ref: string };
        if (state.branches.has(q.branch))
          return fail(reply, 400, 'Branch already exists');
        const from = branchOf(q.ref);
        if (!from) return fail(reply, 400, 'Invalid reference name');
        state.branches.set(q.branch, { ...from, files: new Map(from.files) });
        return reply.code(201).send(branchView(q.branch));
      });
      api.delete('/repository/branches/:branch', (request, reply) => {
        const name = (request.params as { branch: string }).branch;
        if (!state.branches.has(name))
          return fail(reply, 404, '404 Branch Not Found');
        if (state.protectedBranches.has(name))
          return fail(reply, 403, '403 Forbidden');
        state.branches.delete(name);
        return reply.code(204).send();
      });
      api.post('/repository/commits', (request, reply) => {
        const b = request.body as {
          branch: string;
          commit_message: string;
          actions: { action: string; file_path: string; content?: string }[];
        };
        const branch = state.branches.get(b.branch);
        if (!branch)
          return fail(
            reply,
            400,
            'You can only create or edit files when you are on a branch',
          );
        if (state.protectedBranches.get(b.branch)?.push === 0) {
          return fail(
            reply,
            403,
            'You are not allowed to push into this branch',
          );
        }
        for (const a of b.actions) {
          if (a.action === 'delete') branch.files.delete(a.file_path);
          else branch.files.set(a.file_path, a.content ?? '');
        }
        branch.sha = sha();
        branch.title = b.commit_message.split('\n')[0]!;
        return reply.code(201).send({
          id: branch.sha,
          short_id: branch.sha.slice(0, 8),
          title: branch.title,
          author_email: 'bot@gitlab.fixture',
          web_url: `https://gitlab.fixture/${config.project}/-/commit/${branch.sha}`,
        });
      });
      api.get('/merge_requests', (request) => {
        const s = (request.query as { state?: string }).state ?? 'all';
        return state.mergeRequests
          .filter((m) => s === 'all' || m.state === s)
          .map(mrView);
      });
      api.get('/merge_requests/:iid', (request, reply) => {
        const mr = mrOf(request);
        return mr ? mrView(mr) : fail(reply, 404, '404 Not found');
      });
      api.post('/merge_requests', (request, reply) => {
        const b = request.body as {
          source_branch: string;
          target_branch: string;
          title: string;
          description?: string;
        };
        if (
          !state.branches.has(b.source_branch) ||
          !state.branches.has(b.target_branch)
        ) {
          return fail(reply, 400, 'Invalid branch');
        }
        const mr: MergeRequest = {
          iid: state.mergeRequests.length + 1,
          title: b.title,
          description: b.description ?? '',
          state: 'opened',
          source_branch: b.source_branch,
          target_branch: b.target_branch,
          merge_commit_sha: null,
          notes: [],
        };
        state.mergeRequests.push(mr);
        return reply.code(201).send(mrView(mr));
      });
      api.post('/merge_requests/:iid/notes', (request, reply) => {
        const mr = mrOf(request);
        if (!mr) return fail(reply, 404, '404 Not found');
        const note = {
          id: state.nextNote++,
          body: (request.body as { body: string }).body,
        };
        mr.notes.push(note);
        return reply
          .code(201)
          .send({ ...note, created_at: new Date().toISOString() });
      });
      api.put('/merge_requests/:iid/merge', (request, reply) => {
        const mr = mrOf(request);
        if (!mr) return fail(reply, 404, '404 Not found');
        if (state.retargetOnMerge?.iid === mr.iid) {
          mr.target_branch = state.retargetOnMerge.targetBranch;
          state.retargetOnMerge = null;
        }
        if (mr.state !== 'opened')
          return fail(reply, 405, '405 Method Not Allowed');
        const source = state.branches.get(mr.source_branch)!;
        const want = (request.body as { sha?: string } | null)?.sha;
        if (want && want !== source.sha)
          return fail(reply, 409, 'SHA does not match HEAD of source branch');
        const target = state.branches.get(mr.target_branch)!;
        target.files = new Map(source.files);
        target.sha = sha();
        target.title = `Merge branch '${mr.source_branch}' into '${mr.target_branch}'`;
        mr.state = 'merged';
        mr.merge_commit_sha = target.sha;
        return mrView(mr);
      });
      api.get('/pipelines', () => []);
      api.post('/protected_branches', (request, reply) => {
        const b = request.body as {
          name: string;
          push_access_level: number;
          merge_access_level: number;
        };
        if (state.protectedBranches.has(b.name))
          return fail(reply, 409, 'Protected branch already exists');
        state.protectedBranches.set(b.name, {
          push: b.push_access_level,
          merge: b.merge_access_level,
        });
        return reply.code(201).send({
          name: b.name,
          push_access_levels: [
            { access_level_description: levelName(b.push_access_level) },
          ],
          merge_access_levels: [
            { access_level_description: levelName(b.merge_access_level) },
          ],
          allow_force_push: false,
        });
      });
      api.get('/protected_branches/:name', (request, reply) => {
        const name = (request.params as { name: string }).name;
        const p = state.protectedBranches.get(name);
        if (!p) return fail(reply, 404, '404 Not found');
        return {
          name,
          push_access_levels: [{ access_level_description: levelName(p.push) }],
          merge_access_levels: [
            { access_level_description: levelName(p.merge) },
          ],
          allow_force_push: false,
        };
      });
      api.delete('/protected_branches/:name', (request, reply) => {
        const name = (request.params as { name: string }).name;
        if (!state.protectedBranches.delete(name))
          return fail(reply, 404, '404 Not found');
        return reply.code(204).send();
      });
      api.put('/variables/:key', (request, reply) => {
        const key = (request.params as { key: string }).key;
        if (!state.variables.has(key))
          return fail(reply, 404, '404 Variable Not Found');
        const b = request.body as {
          value: string;
          protected: boolean;
          masked: boolean;
        };
        state.variables.set(key, b);
        return { key, ...b, variable_type: 'env_var' };
      });
      api.post('/variables', (request, reply) => {
        const b = request.body as {
          key: string;
          value: string;
          protected: boolean;
          masked: boolean;
        };
        if (state.variables.has(b.key))
          return fail(reply, 400, 'has already been taken');
        state.variables.set(b.key, {
          value: b.value,
          protected: b.protected,
          masked: b.masked,
        });
        return reply.code(201).send({ ...b, variable_type: 'env_var' });
      });
      done();
    },
    { prefix: '/api/v4/projects/:project' },
  );
}

/** A Fastify instance serving only this fixture under `/gitlab`, for in-process use by manar-api's tests. */
export function buildGitLabFixtureApp(
  options: GitLabFixtureOptions = {},
): FastifyInstance {
  const app = Fastify({ logger: false });
  void app.register(gitlabFixtureRoutes, { ...options, prefix: '/gitlab' });
  return app;
}
