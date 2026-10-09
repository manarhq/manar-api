# ADR-0012 — A typed GitLab connector for one project, governed per branch and merge request

- **Status:** ACCEPTED
- **Date:** 2026-10-09
- **Phase:** packs (ADR-010 coding agents pack; hackathon demo 21 Oct 2026)
- **Deciders:** engineering judgement; scope and the demo project approved by Mohamed

## Context

ADR-010 makes coding agents (Claude Code, GitHub Copilot agent, Cursor, GitLab Duo) a pack: the
agent works on a repository only through Manar, and Manar holds the GitLab token. Manar had HTTP,
MCP and Microsoft adapters (`src/tools/`). The generic HTTP adapter posts one JSON body to one
endpoint and cannot express GitLab's REST v4 calls, its token header or which effect a call has on
which branch. Policy resource patterns matched exactly or `*` only, so a policy could not say
"every branch of this project, except `main`" without naming every branch in advance.

## Decision

1. **New tool protocol `GITLAB`** (additive enum migration `20261009120000_add_tool_protocol_gitlab`)
   dispatched by `CredentialBrokerService` to `GitLabToolAdapter`, behind the same pipeline as every
   other adapter (decision, approval, kill switches, DLP, audit).
2. **A fixed catalog** in `src/tools/gitlab-actions.ts`: reads `gitlab.repo.file.get`,
   `gitlab.repo.tree.list`, `gitlab.mr.list`, `gitlab.mr.get`, `gitlab.pipeline.status`; changes
   `gitlab.branch.create`, `gitlab.commit.create`, `gitlab.mr.create`, `gitlab.mr.comment`; risky
   `gitlab.mr.merge`, `gitlab.branch.delete` (destructive), `gitlab.branch.protection.change`
   (destructive), `gitlab.project.variable.set`. Tool rows are written from the catalog
   (`pnpm manar gitlab:register`).
3. **The target is the resource.** `group/project` (project-level), `group/project:<branch>`
   (branch-level), `group/project!<iid>` (merge request). Branch and MR never come from params.
   One tool is pinned to one project (`Tool.metadata.project`); a resource for any other project is
   refused before anything is sent.
4. **Prefix patterns in policy.** A policy `resourcePattern` ending in `*` matches by prefix
   (`manar/demo-repo:*`). Task resource selectors stay exact or `*` (they become OpenFGA tuples).
5. **Default coding pack policy** (`gitlabPolicyContent`): a direct commit to, delete of or
   recreate of a protected branch is DENY; protection change and CI variable set are
   APPROVAL_REQUIRED with risk floor 85; merge and branch delete are APPROVAL_REQUIRED; reads,
   branch create, commit to an unprotected branch, MR create and comment are ALLOW inside the
   project (the task's `maxExecutions` is the budget); anything else on the tool is DENY.
6. **Approved changes are bound to what the person saw.** Merge needs `sha` and `targetBranch`
   (both in the approved parameter hash); a read at execution time refuses if the MR is not open,
   was retargeted or has a new head, and GitLab merges only that `sha`. Branch delete is bound to
   the tip `sha`; protection change to the current protection state. A commit is preceded by a read
   that refuses a protected branch. Every precheck fails closed. After a merge, the MR GitLab
   returns is compared with the approved `targetBranch`; a mismatch is recorded as `UNKNOWN` plus an
   audit event `tool.invocation.approval_binding_violated` (it cannot be undone, it is made visible).
7. **GitLab enforces what it can atomically.** The connector's token is a **Developer**-role
   project access token, and the project protects `main` with push = No one, merge = Developers +
   Maintainers. GitLab itself then refuses any direct push or commit to `main` and any delete of a
   protected branch, whatever happens between Manar's read and the write. A merge passes `sha`,
   so GitLab refuses a moved head.
8. **The token goes to one host only.** Sent as `PRIVATE-TOKEN`, only when the tool's base endpoint
   host is also in the operator's `SSRF_ALLOWED_HOSTS` (two independent settings), over HTTPS
   outside development, never through a redirect (`maxRedirects: 0`), and only to a URL whose
   parsed origin and path stay under `<base>/projects/<project>/`. `safeOutboundFetch` now also
   drops `PRIVATE-TOKEN` on any cross-origin hop. Errors carry the status and a fixed word, never
   GitLab's message or the URL.
9. **Hard catalog limits:** a commit cannot touch `.gitlab-ci.yml` or `.gitlab/` (CI runs with the
   project's secrets); a CI variable is written for scope `*`, protected and masked by default, and
   its value is never returned.
10. **Outcome rules** as in ADR-0004: reads retried, mutations sent once; a 5xx, timeout or dropped
    connection after sending is `UNKNOWN`, and so is GitLab's 400 "Deadline Exceeded" (seen live on
    9 Oct: the commit had landed).

## Alternatives considered

- **Generic HTTP adapter with a per-tool template.** Cannot pin branch and MR to the resource or
  bind an approval to an MR head; every check would be prompt-level.
- **Branch in params, protected-branch check only in the connector.** The DENY would not be a
  Manar decision, so it would not show in the decision record or the console as a refusal.
- **Glob or prefix matching in task selectors too.** Needs OpenFGA tuple changes and the
  delegation subset check; not needed while the policy narrows a `*` selector.
- **Parameter conditions in policy rules.** Approval re-evaluation does not have the params
  (only their hash), so a param-based DENY could not be re-checked at redemption.
- **Do nothing.** The coding pack would need the agent to hold a GitLab token.

## Consequences

- Any MCP client (Claude Code through the governed MCP server, ADR-0007) can work on the project:
  read, branch, commit, open an MR at once; merge after a person approves and the agent repeats the
  call.
- Remaining windows, stated:
  - **Merge retarget.** GitLab checks the head `sha` atomically but not the target branch. A
    retarget between the precheck and the merge merges into the other branch; Manar detects it
    afterwards (`approval_binding_violated`, outcome `UNKNOWN`) but cannot prevent it. A merge into
    a protected branch still needs merge rights there.
  - **Branch delete.** GitLab's branch delete has no expected-`sha` condition and returns no tip.
    A push to an unprotected branch between the precheck and the delete is deleted with it and is
    not detected. Protected branches cannot be deleted at all (GitLab refuses).
  - **Protection change.** Bound to the state read just before; a change by someone else in
    between is not detected. With the Developer token GitLab refuses protection changes and CI
    variable writes (403): the actions stay in the catalog and in policy (approval, high risk), and
    work only where a tenant registers a Maintainer token knowingly.
- A `*` task selector plus the policy is the project restriction; a tenant that publishes no policy
  for the tool still has the project pin and the token's own scope (a project access token).
- A project access token can read public projects on the instance; the project pin refuses them.
- Rollback: revert the commits; the enum value stays (PostgreSQL cannot drop one, see the migration).

## Enforcement-label impact

Coding agents acting on GitLab through Manar's MCP server become `governed` for the catalog
actions on the pinned project. Evidence: `src/tools/gitlab-tool.adapter.spec.ts` (fake GitLab),
`test/gitlab-connector.e2e-spec.ts` (DEMO FIXTURE through the governed MCP server),
`docs/reports/2026-10-09-gitlab-live-smoke.md` (live run on `manar/demo-repo`). The agent's local
shell and any git remote it holds its own credentials for stay outside Manar's view.
