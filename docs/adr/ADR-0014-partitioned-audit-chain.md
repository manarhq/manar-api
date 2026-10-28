# ADR-0014 — Split each tenant's audit chain into 64 partitions with group commit and signed checkpoints

- **Status:** ACCEPTED
- **Date:** 2026-10-28
- **Phase:** R2 foundations, plan F1 (`../docs/superpowers/plans/2026-10-28-r2-f1-audit-scale.md`)
- **Deciders:** Mohamed (design approved 28 Oct 2026; one signing key per tenant); engineering judgement for the details

## Context

`AuditService.record` appended every event to one hash chain per tenant. It locked the single
`audit_chain_state` row with `SELECT ... FOR UPDATE` in every write, so all audit writes in a
tenant ran one at a time. Measured ceiling: about 45–50 events/s. The organisation-scale design
(`../docs/superpowers/specs/2026-10-28-manar-fleet-federation-design.md` §7.1) targets 5,000
decisions/s per instance. Its HUB anchors per-instance checkpoints (§8.3), and those don't exist
yet. Addendum 01's "no Merkle tree for November" is superseded for this release line by that
design.

## Decision

- **64 partitions per tenant.** `partitionFor` (`src/audit/audit-partition.ts`) keys an event by
  the agent it is about: the actor if it is an agent, else `data.agentId`, else the actor. Each
  partition is its own hash chain. `AuditEvent` gains `partition` and a dense `partitionSeq`.
  `previousHash` now means the previous event in the same partition. The `eventHash` formula is
  unchanged.
- **`audit_partition_state`** (one row per partition) replaces the `audit_chain_state` singleton.
  The migration turns every existing event into partition 0 in its original order and copies the
  singleton into partition 0's row, so old chains verify unchanged. It then **drops
  `audit_chain_state`**. This is the destructive step this ADR covers.
- **Group commit.** `AuditBatcher` queues events per tenant and writes up to 500 events, or
  whatever arrived within 5 ms, in one transaction. That transaction locks only the touched
  partition rows, in ascending order, so two replicas can't deadlock. The caller's promise settles
  when its batch commits, so record-before-execution still holds. `recordInTransaction` (ADR-0010)
  bypasses the batcher and locks its one partition inside the caller's transaction.
- **Second guard.** The unique index on `(partition, partitionSeq)` means a fork can never
  commit, even if the lock were removed. `test/audit-chain.e2e-spec.ts` ("two app instances")
  fails without the lock, on that index.
- **Signed checkpoints (SEALs)** every second, with RFC 6962 Merkle roots per partition range,
  Ed25519 signatures and one key per tenant. Inclusion proofs follow in the same plan.

### Hardening added during the build (automated security review)

- **Anchors are signed by retention.** Retention seals first, verifies the whole log, and refuses
  to prune a log that does not verify.
- **SEAL freshness uses the SEAL's signed time.** Event timestamps are not trusted for it.
- **Signed heads are checked.** Every head in the last SEAL must still exist or have been pruned
  by retention.
- **A tenant key with no SEALs is a broken log,** including when the log is empty.
- **Evidence verification checks every proof against the real tenant key.** It accepts a missing
  proof only for a stored, not-yet-sealed event.
- **`partitionSeq` is a 32-bit integer.** A BigInt made `JSON.stringify` of a row throw; 32 bits
  is about 870 years of headroom per partition at the design peak.
- **Residual:** an unsigned anchor planted in partition 0 is accepted (pre-partitioning history).
  Keeping the latest SEAL outside the tenant database comes with the HUB (plan H2).

## Alternatives considered

- **Do nothing:** caps the product at ~50 audited decisions/s per tenant, two orders of magnitude
  below the design target.
- **An advisory lock instead of a row lock:** same serialisation, with less visibility.
- **Async audit (write after acting):** breaks record-before-execution (ADR-003). Rejected.
- **Per-agent chains:** unbounded number of chain heads, and checkpoints grow with agent count.
  64 partitions keep checkpoints bounded while giving the parallelism.

## Consequences

- Throughput scales with the number of partitions touched per batch. The R1 target of 1,000
  events/s is measured in `GATE-R2-F1.md`. 5,000/s is proven later on lab hardware (plan P).
- Verification walks 64 partitions; an empty tenant costs 64 small queries.
- **Rollback:** the migration header gives the SQL. It is only valid while every event is still in
  partition 0. After new code writes other partitions, the old single-chain code can't verify the
  log, so roll forward.

## Enforcement-label impact

None. The audit log is the record behind every label, not a label itself. No action path changes
label.
