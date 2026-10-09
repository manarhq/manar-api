# ADR-0011: Helpdesk and joiner/leaver Graph actions; a temporary password goes only to its approver

- **Status:** ACCEPTED
- **Date:** 2026-10-09
- **Phase:** packs (workspace ADR-010), on the ADR-0004 connector
- **Deciders:** engineering judgement; scope and tenant changes approved by Mohamed

## Context

Workspace ADR-010 makes IT helpdesk and HR joiner/leaver packs on Microsoft Graph, demoed live on
the Fixio tenant on 21 Oct 2026. They need actions the ADR-0004 catalog lacked: MFA
re-registration, unlock, group membership, user creation and offboarding. Several are more than
one Graph request. A helpdesk password reset is useless if nobody learns the new password, but the
agent must never hold it, and ADR-0004 §8 discarded it on purpose.

## Decision

1. **Multi-step catalog actions.** A catalog entry has either `build` (one request) or `run`
   (several requests through the adapter's per-request `call`, which keeps ADR-0004's retry and
   UNKNOWN rules per request: GETs retried, changes sent once). Steps run in order and stop at the
   first failure. If a change already happened, the outcome is UNKNOWN with
   `partial: done <steps>; <step> failed (<code>)`, so it is reconciled by a person, never retried.
2. **New actions** (`src/tools/microsoft-actions.ts`; default policy from `microsoftPolicyContent`):

   | Action                      | Resource                      | Flags                                | Default policy    |
   | --------------------------- | ----------------------------- | ------------------------------------ | ----------------- |
   | `entra.group.members.list`  | group id                      | read                                 | ALLOW             |
   | `entra.user.mfa.reset`      | user                          | mutating, destructive                | APPROVAL_REQUIRED |
   | `entra.user.unlock`         | user                          | mutating                             | APPROVAL_REQUIRED |
   | `entra.group.member.add`    | `<group id>:<user id or UPN>` | mutating                             | APPROVAL_REQUIRED |
   | `entra.group.member.remove` | `<group id>:<user id or UPN>` | mutating, destructive                | APPROVAL_REQUIRED |
   | `entra.user.create`         | new UPN                       | mutating, risk floor 70              | APPROVAL_REQUIRED |
   | `entra.user.offboard`       | user                          | mutating, destructive, risk floor 80 | APPROVAL_REQUIRED |

   A membership change has two targets, so both are in `resource` and both are authorized; a
   group in `params` could not be restricted by selectors or policy.

3. **What Graph supports, said plainly.**
   - MFA re-registration: list the user's methods, delete each one Graph can delete (authenticator,
     OATH, FIDO2, Windows Hello, platform credential, temporary access pass, email, then phone,
     mobile last), keep the password, revoke sessions. The user registers again at next sign-in
     where MFA is required. Not atomic.
   - Unlock: Graph has no call that clears Entra smart lockout; it ends on its own. The action
     re-enables the account (`accountEnabled=true`).
   - Offboard: disable, revoke sessions, remove every group membership Graph can change (dynamic
     groups are reported as kept). **Mailbox and OneDrive handover are declared-only**: mailbox
     delegation or conversion is Exchange Online, not Graph; OneDrive access for a manager needs
     `Sites.FullControl.All`, which the app does not hold, and the demo users are unlicensed. The
     result carries both statements.
   - Create: disabled unless `accountEnabled: true`; groups are added with
     `entra.group.member.add`.
4. **Approver handover.** `entra.user.password.reset` and `entra.user.create` generate a temporary
   password inside Manar and set `forceChangePasswordNextSignIn: true`. The adapter returns it in
   `ToolInvocationResult.handover`. `CredentialBrokerService` takes `handover` out of the result
   before the invocation row, audit, DLP or the response. If the execution redeemed an approval
   grant, the value goes to OpenBao **KV v1** at `handover/<tenant>/<approval request>` with its
   creation time; otherwise (the policy allowed it outright) it is discarded, which is the old
   lockout behaviour. The agent's result says only where it went. If OpenBao fails the value is
   discarded too: there is no other store.
5. **Collection.** `POST /approvals/:id/handover` (human JWT, `Cache-Control: no-store`) returns
   the value once, only to the person recorded as having approved that request; it then deletes
   it. 404 when there is nothing (not executed, collected, expired); 503
   `enforcement_dependency_unavailable` when OpenBao fails. Audit `approval.handover_collected`
   carries the field names, never the value.
6. **Retention.** KV v1 has no versions, so a delete is final. A value older than 24 h is never
   handed out, and a sweep in each API process (every 10 minutes) deletes it. A first version used
   KV v2 with `delete_version_after`, which only soft-deletes; review caught it before merge.
7. **Live registration.** `manar microsoft:register` upserts a live Microsoft tool and syncs its
   `ToolAction` rows from the catalog (ADR-0004 §9).

## Alternatives considered

- **Return the password in the agent's result.** The agent would hold a credential. Rejected.
- **Show it in the approval UI before execution.** The password does not exist until execution,
  and must not exist if the action is never executed. Rejected.
- **Store it in PostgreSQL, encrypted.** A second secret store with its own key management.
  OpenBao already holds the tool credentials. Rejected.
- **KV v2 with check-and-set** would make collection atomic but keeps soft-deleted versions.
  KV v1 read-then-delete is not atomic: two simultaneous collects by the same approver could both
  succeed. Accepted, noted in `handover.store.ts`.
- **Membership with the group in `params`.** Not restrictable. Rejected (§2).

## Consequences

- Helpdesk and joiner/leaver packs run on the existing gateway; nothing new on the decision path.
- `ToolInvocationResult` has one more field that must never leave the broker; the broker unit
  tests and the e2e grep the response, invocations, decisions, approval requests and audit rows
  for the passwords.
- The console has no collect button yet; the demo uses `POST /approvals/:id/handover` from a
  script. Adding the button is a manar-web change.
- Live on Fixio (9 Oct 2026, manar.demo.* users only): read, group add/remove, password reset
  with handover, MFA reset (no methods registered on the demo users, so none removed), unlock,
  offboard and re-enable all ran through approvals. Graph reads right after a change can show the
  old value for a few seconds (replica lag).

## Enforcement-label impact

None for AI systems. The new actions are `governed` (decided, approved, executed by Manar). Mailbox
and OneDrive handover are `declared-only`.
