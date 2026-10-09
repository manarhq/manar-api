import type { AddressInfo } from 'node:net';
import type { ConfigService } from '@nestjs/config';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import {
  buildGitLabFixtureApp,
  GITLAB_FIXTURE_DEFAULTS,
} from '../../packages/demo-soc-tools/src/gitlab/fixture';
import {
  findGitLabAction,
  GITLAB_ACTIONS,
  parseGitLabResource,
} from './gitlab-actions';
import { GitLabToolAdapter } from './gitlab-tool.adapter';
import type { ToolActionRecord, ToolRecord } from './tool-registry.service';

/**
 * `GitLabToolAdapter` against the in-process DEMO FIXTURE (a fake GitLab,
 * `packages/demo-soc-tools/src/gitlab/fixture.ts`) over real loopback HTTP.
 * Proves request shapes, the project pin, the protected-branch precheck and
 * outcome mapping; says nothing about a live GitLab.
 */

const P = GITLAB_FIXTURE_DEFAULTS.project;
const TOKEN = GITLAB_FIXTURE_DEFAULTS.token;

function config(allowLoopback = true): ConfigService<AppConfig, true> {
  const values: Record<string, unknown> = {
    NODE_ENV: 'test',
    SSRF_ALLOWED_HOSTS: '127.0.0.1',
    SSRF_ALLOW_LOOPBACK: allowLoopback,
  };
  return { get: (key: string) => values[key] } as never;
}

function action(name: string): ToolActionRecord {
  const def = findGitLabAction(name);
  return {
    id: `row-${name}`,
    toolId: 'tool',
    name,
    description: null,
    riskBaseScore: def?.riskBaseScore ?? 0,
    inputSchema: null,
    outputSchema: null,
    mutating: def?.mutating ?? true,
    destructive: def?.destructive ?? true,
    approvalDefault: false,
    classification: 'INTERNAL',
  };
}

interface Recorded {
  method: string;
  path: string;
  query: Record<string, string>;
  body: Record<string, unknown> | null;
}

describe('GitLabToolAdapter (against the DEMO FIXTURE)', () => {
  let fixture: FastifyInstance;
  let base: string;
  let adapter: GitLabToolAdapter;

  beforeEach(async () => {
    fixture = buildGitLabFixtureApp();
    await fixture.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(fixture.server.address() as AddressInfo).port}/gitlab`;
    adapter = new GitLabToolAdapter(config());
  });
  afterEach(async () => {
    await fixture.close();
  });

  const tool = (metadata: Record<string, unknown> = {}): ToolRecord => ({
    id: 'tool-gitlab',
    name: 'gitlab-demo',
    type: 'SCM',
    vendor: 'GitLab',
    description: null,
    baseEndpoint: `${base}/api/v4`,
    protocol: 'GITLAB',
    credentialReference: { provider: 'OPENBAO', reference: 'unused' },
    enabled: true,
    metadata: { project: P, requestTimeoutMs: 1_000, ...metadata },
  });
  const invoke = (
    name: string,
    resource: string,
    params: unknown = {},
    t: ToolRecord = tool(),
    credential: string = TOKEN,
  ) => adapter.invoke(t, action(name), resource, params, credential);

  const control = async <T>(path: string, body?: unknown): Promise<T> =>
    (
      await fetch(`${base}/_fixture/${path}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers:
          body === undefined ? {} : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    ).json() as Promise<T>;
  const requests = async () =>
    (await control<{ requests: Recorded[] }>('requests')).requests;
  const state = () =>
    control<{
      branches: Record<string, { files: Record<string, string> }>;
      protectedBranches: string[];
      mergeRequests: { iid: number; state: string; notes: unknown[] }[];
      variables: string[];
    }>('state');
  const projectPath = `/api/v4/projects/${encodeURIComponent(P)}`;

  it('declares the catalog with the agreed change and risk flags', () => {
    const flags = Object.fromEntries(
      GITLAB_ACTIONS.map((a) => [a.name, [a.mutating, a.destructive]]),
    );
    expect(flags).toEqual({
      'gitlab.repo.file.get': [false, false],
      'gitlab.repo.tree.list': [false, false],
      'gitlab.mr.list': [false, false],
      'gitlab.mr.get': [false, false],
      'gitlab.pipeline.status': [false, false],
      'gitlab.branch.create': [true, false],
      'gitlab.commit.create': [true, false],
      'gitlab.mr.create': [true, false],
      'gitlab.mr.comment': [true, false],
      'gitlab.mr.merge': [true, false],
      'gitlab.branch.delete': [true, true],
      'gitlab.branch.protection.change': [true, true],
      'gitlab.project.variable.set': [true, false],
    });
  });

  it('parses resources strictly', () => {
    expect(parseGitLabResource('branch', `${P}:feature/x`)).toEqual({
      project: P,
      branch: 'feature/x',
    });
    expect(parseGitLabResource('mr', `${P}!12`)).toEqual({
      project: P,
      iid: 12,
    });
    for (const bad of [
      `${P}:refs/heads/main`,
      `${P}:a..b`,
      `${P}:-x`,
      `${P}:x.lock`,
      `${P}:`,
      'x:main',
      '../x:main',
    ]) {
      expect(parseGitLabResource('branch', bad)).toBeUndefined();
    }
    expect(parseGitLabResource('mr', `${P}!0`)).toBeUndefined();
    expect(parseGitLabResource('project', `${P}:main`)).toBeUndefined();
  });

  it('reads a file, decoded, with the token sent as PRIVATE-TOKEN only to the project path', async () => {
    const result = await invoke('gitlab.repo.file.get', P, {
      path: 'src/greeting.py',
      ref: 'main',
    });
    expect(result).toMatchObject({
      success: true,
      data: { file_path: 'src/greeting.py' },
    });
    expect((result.data as { content: string }).content).toContain('def greet');
    const [req] = await requests();
    expect(req!.path).toBe(`${projectPath}/repository/files/src%2Fgreeting.py`);
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  it('refuses a resource for another project before sending anything', async () => {
    const result = await invoke('gitlab.repo.tree.list', 'manar/manar-api');
    expect(result).toEqual({
      success: false,
      errorMessage: 'resource_outside_tool_project',
    });
    const branch = await invoke('gitlab.branch.delete', 'other/repo:develop');
    expect(branch.errorMessage).toBe('resource_outside_tool_project');
    expect(await requests()).toHaveLength(0);
  });

  it('refuses invalid params and the wrong resource kind before sending anything', async () => {
    expect(
      (
        await invoke('gitlab.commit.create', `${P}:develop`, {
          message: 'x',
          actions: [
            { action: 'update', file_path: '.gitlab-ci.yml', content: 'evil' },
          ],
        })
      ).errorMessage,
    ).toMatch(/Invalid params/);
    expect(
      (
        await invoke('gitlab.commit.create', `${P}:develop`, {
          message: 'x',
          actions: [{ action: 'update', file_path: '../x', content: '' }],
        })
      ).errorMessage,
    ).toMatch(/Invalid params/);
    expect((await invoke('gitlab.mr.merge', P)).errorMessage).toMatch(
      /Invalid resource/,
    );
    expect(
      (await invoke('gitlab.repo.tree.list', P, { extra: 1 })).errorMessage,
    ).toMatch(/Invalid params/);
    expect(await requests()).toHaveLength(0);
  });

  it('branch, commit, merge request, comment and merge, as a coding agent would', async () => {
    expect(
      await invoke('gitlab.branch.create', `${P}:feature/hello`, {
        ref: 'main',
      }),
    ).toMatchObject({
      success: true,
      data: { name: 'feature/hello', protected: false },
    });
    const commit = await invoke('gitlab.commit.create', `${P}:feature/hello`, {
      message: 'docs: say hello',
      actions: [
        { action: 'create', file_path: 'HELLO.md', content: 'hello\n' },
      ],
    });
    expect(commit).toMatchObject({
      success: true,
      data: { title: 'docs: say hello' },
    });
    const mr = await invoke('gitlab.mr.create', P, {
      sourceBranch: 'feature/hello',
      targetBranch: 'main',
      title: 'docs: say hello',
    });
    expect(mr).toMatchObject({
      success: true,
      data: { iid: 1, state: 'opened', author: 'project_bot' },
    });
    expect(JSON.stringify(mr.data)).not.toContain('avatar_url');
    expect(
      (
        await invoke('gitlab.mr.comment', `${P}!1`, {
          body: 'Ready for review',
        })
      ).success,
    ).toBe(true);
    const head = (await invoke('gitlab.mr.get', `${P}!1`)).data as {
      sha: string;
    };
    const merged = await invoke('gitlab.mr.merge', `${P}!1`, { sha: head.sha });
    expect(merged).toMatchObject({ success: true, data: { state: 'merged' } });
    const s = await state();
    expect(s.branches.main!.files['HELLO.md']).toBe('hello\n');
    expect(s.mergeRequests[0]).toMatchObject({ state: 'merged', notes: [{}] });
  });

  it('refuses a commit to a protected branch after one read, never sending the commit', async () => {
    const result = await invoke('gitlab.commit.create', `${P}:main`, {
      message: 'direct push',
      actions: [{ action: 'update', file_path: 'README.md', content: 'x' }],
    });
    expect(result).toEqual({
      success: false,
      errorMessage: 'protected_branch',
    });
    expect((await requests()).map((r) => r.method)).toEqual(['GET']);
  });

  it('a commit to a branch that does not exist is a failure, not a new branch', async () => {
    const result = await invoke('gitlab.commit.create', `${P}:nope`, {
      message: 'x',
      actions: [{ action: 'create', file_path: 'a', content: '' }],
    });
    expect(result).toEqual({
      success: false,
      errorMessage: 'HTTP 404 not_found',
    });
  });

  it('protects and unprotects a branch, deletes an unprotected one', async () => {
    await invoke('gitlab.branch.create', `${P}:tmp`, { ref: 'main' });
    expect(
      await invoke('gitlab.branch.protection.change', `${P}:tmp`, {
        protect: true,
      }),
    ).toMatchObject({
      success: true,
      data: { name: 'tmp', push: ['No one'], merge: ['Maintainers'] },
    });
    expect(
      (await invoke('gitlab.branch.delete', `${P}:tmp`)).errorMessage,
    ).toBe('HTTP 403 forbidden');
    expect(
      (
        await invoke('gitlab.branch.protection.change', `${P}:tmp`, {
          protect: false,
        })
      ).success,
    ).toBe(true);
    expect((await invoke('gitlab.branch.delete', `${P}:tmp`)).success).toBe(
      true,
    );
    expect(Object.keys((await state()).branches)).not.toContain('tmp');
  });

  it('sets a CI variable (create, then update) and never returns its value', async () => {
    const created = await invoke('gitlab.project.variable.set', P, {
      key: 'DEPLOY_ENV',
      value: 's3cr3t-value',
    });
    expect(created).toMatchObject({
      success: true,
      data: { key: 'DEPLOY_ENV', masked: true, protected: true },
    });
    const updated = await invoke('gitlab.project.variable.set', P, {
      key: 'DEPLOY_ENV',
      value: 'other-value',
    });
    expect(updated.success).toBe(true);
    expect(JSON.stringify([created, updated])).not.toContain('value"');
    expect((await requests()).map((r) => r.method)).toEqual([
      'PUT',
      'POST',
      'PUT',
    ]);
  });

  it('retries a read on 5xx, sends a mutation once and calls a 5xx after sending UNKNOWN', async () => {
    await control('faults', {
      method: 'GET',
      path: `${projectPath}/merge_requests`,
      status: 502,
    });
    expect((await invoke('gitlab.mr.list', P)).success).toBe(true);

    await control('faults', {
      method: 'POST',
      path: `${projectPath}/repository/branches`,
      status: 503,
    });
    const created = await invoke('gitlab.branch.create', `${P}:x`, {
      ref: 'main',
    });
    expect(created).toEqual({
      success: false,
      errorMessage: 'HTTP 503',
      outcomeUnknown: true,
    });
    expect((await requests()).filter((r) => r.method === 'POST')).toHaveLength(
      1,
    );
  });

  it('treats a Gitaly deadline on a mutation as UNKNOWN (the write may have landed)', async () => {
    await control('faults', {
      method: 'POST',
      path: `${projectPath}/merge_requests`,
      status: 400,
      message: '4:Deadline Exceeded.',
    });
    const result = await invoke('gitlab.mr.create', P, {
      sourceBranch: 'develop',
      targetBranch: 'main',
      title: 't',
    });
    expect(result).toEqual({
      success: false,
      errorMessage: 'HTTP 400 storage_timeout',
      outcomeUnknown: true,
    });
  });

  it('a refused mutation (4xx) is a definite failure; a wrong token is 401', async () => {
    expect(
      await invoke('gitlab.branch.create', `${P}:develop`, { ref: 'main' }),
    ).toEqual({
      success: false,
      errorMessage: 'HTTP 400 rejected',
    });
    expect(
      (await invoke('gitlab.mr.list', P, {}, tool(), 'wrong')).errorMessage,
    ).toBe('HTTP 401 unauthorized');
  });

  it('needs HTTPS outside development and refuses a malformed tool config', async () => {
    const strict = new GitLabToolAdapter(config(false));
    expect(
      await strict.invoke(tool(), action('gitlab.mr.list'), P, {}, TOKEN),
    ).toEqual({
      success: false,
      errorMessage: 'blocked_by_outbound_url_policy',
    });
    expect(
      (await invoke('gitlab.mr.list', P, {}, tool({ project: '../x' })))
        .errorMessage,
    ).toBe('invalid_gitlab_tool_config');
    expect(await requests()).toHaveLength(0);
  });
});
