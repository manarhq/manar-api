# Decision path without per-request reads (R2 F4, spec §7.2-7.3)

The synchronous decision touches PostgreSQL, Valkey and OpenFGA, plus in-process evaluation
(`src/authorization/decision-path-dependencies.spec.ts` enforces the import graph). F4 takes the
kill-switch and relationship reads off those stores for the common case. **Every cache below has a
stated staleness bound, and a failure past the bound is DENY `enforcement_dependency_unavailable`.**

| Control                                    | Where                                                  | Bound                                                           | When its store is unreachable                                                                                |
| ------------------------------------------ | ------------------------------------------------------ | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Kill switches, quarantine, AI-system state | `KillSwitchService.checkAll`, `KillSwitchEpochService` | **2 s** (`KILL_SWITCH_CACHE_MAX_AGE_MS`, 0 = off, max 10 s)     | epoch unreadable: PostgreSQL read directly and nothing cached; PostgreSQL also down: throws, pipeline denies |
| OpenFGA relationship checks                | `OpenFgaClientService.check`                           | **3 s**, ALLOW only (`OPENFGA_CACHE_TTL_MS`, 0 = off, max 10 s) | expired entry and OpenFGA down: throws, pipeline denies                                                      |
| Agent rate limits                          | `RedisThrottlerStorageService` (GCRA)                  | none: every check is one atomic Valkey call                     | agent surface returns 503 `enforcement_dependency_unavailable`                                               |
| LLM token budgets                          | `TokenLeaseService`                                    | a lease record lives 24 h                                       | rejects; the caller denies                                                                                   |

## Kill switches

- A cache entry is keyed `tenant|agent|tool` and holds the result, the epoch pair read when it was
  loaded and its age.
- Epochs are two Valkey counters, `manar:ks-epoch:platform` and `manar:ks-epoch:tenant:<id>`,
  read together with one `MGET` per check. A different value, or an age over the bound, rereads
  PostgreSQL.
- Every writer of a stop condition bumps after its commit: tenant/agent/group/tool switches
  (`KillSwitchService`), the platform switch (activate and the staff release), platform
  suspension, agent quarantine and release, AI-system lifecycle changes and agent links. A bump
  that fails is logged; other replicas then catch up within the 2 s bound.
- Spec §7.2 names Postgres `LISTEN/NOTIFY` for the refresh. Tenant data lives in one database per
  tenant, so F4 uses the Valkey epoch instead (one connection, no per-tenant listeners). The
  correctness check is the same: a changed epoch rereads.
- Not cached: the agent's own status and the task row (still read from PostgreSQL per request;
  deferred).

## OpenFGA

- Only ALLOW results are reused, keyed by the whole tuple (tenant is inside the user and object ids).
- A tuple delete through this process clears the cache. On another replica a revoked grant is
  honoured within the bound.
- Redemption of an approved grant (the high-risk path) passes `consistency: 'high'` and always asks
  OpenFGA.

## GCRA

`ttl` and `limit` of each throttler config become an emission interval of `ttl / limit` and a burst
of `limit`. Time comes from Valkey. The throttler's block duration is unused; the reply carries the
wait until the next slot.

## Token leases

`setBudget`, `lease(tenant, budget, leaseId, block)` and `release(..., unspent)`; atomic, idempotent
per lease id, a missing budget grants nothing, and an unreleased lease counts as spent. Nothing
calls it yet: the host side and the Hub → member → host hierarchy belong to the fleet work.

## Rollback

No migration. Set `KILL_SWITCH_CACHE_MAX_AGE_MS=0` and `OPENFGA_CACHE_TTL_MS=0` to read every time;
the GCRA change is code only.
