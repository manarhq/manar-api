# GitLab connector live smoke run, 9 Oct 2026

**What ran:** manar-api `feat/gitlab-connector` (ADR-0012) on the local stack, tool `gitlab-demo`
(protocol `GITLAB`, `https://gitlab.example.com/api/v4`, pinned to `manar/demo-repo`), the coding pack
policy (`gitlabPolicyContent`), and a task for the Claude agent (all 13 actions, selector `*`, risk
ceiling 50, execution budget 60). Every call went through Manar's governed MCP server over mTLS,
the same `tools/call` the Claude Code bridge sends (`~/manar-demo/coding/smoke.mjs`). Approvals were
decided by `demo-approver` through the console API. GitLab is live (`DataOrigin: LIVE`); no fixture.

**Token:** a project access token for `manar/demo-repo` only, **Developer** role, scope `api`,
expires 2026-11-07, piped from GitLab straight into OpenBao `secret/tools/gitlab-demo`; never
printed or written to disk. `main` is protected: push No one, merge Developers + Maintainers.
`SSRF_ALLOWED_HOSTS` lists `gitlab.example.com` (required by the connector besides the tool row).

## Result (third run, all as expected)

| #   | Step                              | Action                            | Resource                             | Manar    | Outcome / reason                  | Note                   |
| --- | --------------------------------- | --------------------------------- | ------------------------------------ | -------- | --------------------------------- | ---------------------- |
| 0   | tools/list                        |                                   |                                      |          | 13 gitlab-demo tools              |                        |
| 1   | read a file                       | `gitlab.repo.file.get`            | `manar/demo-repo`                    | EXECUTED | SUCCESS                           | 615 bytes              |
| 2   | list the tree                     | `gitlab.repo.tree.list`           | `manar/demo-repo`                    | EXECUTED | SUCCESS                           | 8 entries              |
| 3   | list open MRs                     | `gitlab.mr.list`                  | `manar/demo-repo`                    | EXECUTED | SUCCESS                           | 1 open                 |
| 4   | pipelines                         | `gitlab.pipeline.status`          | `manar/demo-repo`                    | EXECUTED | SUCCESS                           | 0 pipelines            |
| 5   | create a branch                   | `gitlab.branch.create`            | `manar/demo-repo:smoke/202610090441` | EXECUTED | SUCCESS                           |                        |
| 6   | commit to it                      | `gitlab.commit.create`            | `manar/demo-repo:smoke/202610090441` | EXECUTED | SUCCESS                           | 3f890211               |
| 7   | open an MR into main              | `gitlab.mr.create`                | `manar/demo-repo`                    | EXECUTED | SUCCESS                           | !6                     |
| 8   | comment on it                     | `gitlab.mr.comment`               | `manar/demo-repo!6`                  | EXECUTED | SUCCESS                           |                        |
| 9   | commit straight to protected main | `gitlab.commit.create`            | `manar/demo-repo:main`               | DENIED   | policy_denied                     | nothing sent to GitLab |
| 10  | touch another project             | `gitlab.branch.create`            | `manar/manar-api:x`                  | DENIED   | policy_denied                     | nothing sent to GitLab |
| 11  | read the MR (head sha)            | `gitlab.mr.get`                   | `manar/demo-repo!6`                  | EXECUTED | SUCCESS                           | 3f890211               |
| 12  | merge it                          | `gitlab.mr.merge`                 | `manar/demo-repo!6`                  | PENDING  | policy_requires_approval          | nothing merged yet     |
| 13  | a person approves                 |                                   |                                      | APPROVED | demo-approver via the console API |                        |
| 14  | same merge call again             | `gitlab.mr.merge`                 | `manar/demo-repo!6`                  | EXECUTED | SUCCESS                           | MR state merged        |
| 15  | unprotect main                    | `gitlab.branch.protection.change` | `manar/demo-repo:main`               | PENDING  | policy_requires_approval          | high risk              |
| 16  | a person refuses                  |                                   |                                      | DENIED   | demo-approver via the console API |                        |
| 17  | set a CI variable                 | `gitlab.project.variable.set`     | `manar/demo-repo`                    | PENDING  | policy_requires_approval          | high risk              |
| 18  | a person refuses                  |                                   |                                      | DENIED   | demo-approver via the console API |                        |
| 19  | delete the merged branch          | `gitlab.branch.delete`            | `manar/demo-repo:smoke/202610090441` | PENDING  | policy_requires_approval          |                        |
| 20  | a person approves                 |                                   |                                      | APPROVED | demo-approver via the console API |                        |
| 21  | same delete call again            | `gitlab.branch.delete`            | `manar/demo-repo:smoke/202610090441` | EXECUTED | SUCCESS                           |                        |

Risk scores of the approvals (task ceiling 50): merge 75, branch delete 95, protection change 90,
CI variable 85. Tool invocations, decisions, approvals and audit rows for the task, and the API and
worker logs, were searched for the token value: 0 matches.

After the run `~/manar-demo/coding/reset-demo-repo.sh` put the project back to its baseline
(main and develop at the baseline commit, MR !1 open, no other branches, MRs or CI variables).

## Found on the way (fixed in this branch)

1. **Merge recorded as UNKNOWN although it landed** (run 1). GitLab took longer than the 15 s
   request deadline to answer the merge; Manar correctly recorded `UNKNOWN` (the merge had
   happened, merge commit on `main`). Fix: the GitLab request deadline defaults to 60 s.
2. **Merge refused with 405** (run 2). Right after a push, gitlab.example.com reports the MR as
   `preparing`/`checking` for about a minute and refuses a merge. The approved grant was spent on a
   refusal. Fix: the merge precheck re-reads the MR while GitLab is still checking (up to 45 s).
   The GitLab instance's background processing is slow; worth a look by whoever runs it.
3. **Gitaly "Deadline Exceeded" on writes** (while creating the demo project): GitLab answered 400
   although the commit had landed. The connector treats that answer to a mutation as `UNKNOWN`.

## Shared demo tenant

The runs used the shared demo tenant. Its other API (:3000) was an older build that cannot read a
`GITLAB` tool row, so its `GET /tools` failed with 500 while `gitlab-demo` was registered. After the
runs the tool row, its 13 actions and its 63 tool-invocation rows were deleted and the three coding
tasks revoked; `GET /tools` on :3000 answered 200 again. Decisions, approvals and audit events of the
runs were kept. See ADR-0012 ("Mixed builds on one tenant").

## Not covered by this run

- Protection change and CI variable set were refused by the person, so not executed live. With the
  Developer token GitLab refuses both (403) even after approval, by design (ADR-0012).
- No CI pipelines exist on demo-repo (no `.gitlab-ci.yml`), so `gitlab.pipeline.status` returned an
  empty list.
