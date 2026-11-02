# Phase 12b: Container/Kubernetes Hardening & CI Security Scanning — Design

Status: Approved (autonomous execution)
Scope: `manar-api`, `manar-web`, `manar-ai` (infra/pipeline concerns
across all three repos — independent of Phase 12a's application-level
work, safe to run in parallel with it)
Depends on: nothing code-level; depends on every service that needs a
Helm chart actually existing (they all do, as of Phases 1-11a)

## Purpose

Section 82 (Kubernetes from day one — manifests only, **do not deploy
anywhere**), Section 83 (container hardening audit), and Section 77-78
(CI security scanning, git quality gates already partly done in Phase 1).
This phase produces deployable-later artifacts, not a deployment.

## Container hardening audit

Every Dockerfile across `manar-api`, `manar-web`, `manar-ai`, and
`manar-api/packages/demo-soc-tools` was built non-root/multi-stage in
its own phase — do a real audit pass now, not a rubber stamp: confirm
no build toolchain leaks into the final image, confirm `HEALTHCHECK`
still matches real current endpoints (some have changed since their
Dockerfile was written — e.g. new routes added in later phases), confirm
base image tags are still reasonably current (not `latest`, but also not
badly stale), confirm no secrets/`.env` files are ever copied into any
image (`.dockerignore` coverage). Fix anything that's drifted.

## Kubernetes manifests / Helm

A Helm chart per deployable service (`manar-api`'s HTTP app, `manar-api`'s
separate Temporal worker process, `manar-web`, `manar-ai`,
`demo-soc-tools`) — research current official Helm chart conventions.
Each includes: readiness/liveness probes (matching each service's real
`/health/live`/`/health/ready` endpoints), resource requests/limits
(reasonable defaults, documented), a `securityContext` (non-root,
read-only root filesystem where feasible, dropped capabilities),
config via `ConfigMap`, secrets referenced (not embedded) via `Secret`
objects, and `NetworkPolicy` resources expressing the real dependency
graph established across ten-plus phases (e.g. `manar-api`'s HTTP app
needs egress to Postgres/Keycloak/OpenBao/OpenFGA/Temporal/Kafka/Redis/
OpenSearch/`manar-ai`/`demo-soc-tools`; `manar-web` needs egress only to
`manar-api` and Keycloak; nothing needs unrestricted egress). Validate
manifests with `kubeconform`/`kube-linter` (research current versions) —
don't just eyeball YAML.

**Do not deploy anything.** This phase produces chart files in the repos
only. No production-domain configuration, no real cluster interaction.

## CI security scanning

Add to each repo's `.gitlab-ci.yml`, a stage that was deliberately
deferred all the way back in Phase 1 ("Security scanning stages are
explicitly deferred... not stubbed with placeholders"). Now it's time.
Research current versions/setup for: Trivy (dependency + container
image scanning), Gitleaks (secret scanning — should catch anything an
earlier phase might have accidentally committed; run it retroactively
against history too and confirm clean, don't just scan going forward),
Semgrep (SAST), Syft (SBOM generation), kube-linter/kubeconform (the
manifests you just wrote). Don't install redundant tools that solve the
same problem twice (Section 77's explicit guidance). Wire findings to
fail the pipeline on real (not just any) severity threshold you choose
and document.

## Testing

- Each Helm chart renders (`helm template`) without error and passes
  `kubeconform`/`kube-linter`.
- `NetworkPolicy` resources are internally consistent with the actual
  `docker-compose.yml` dependency graph already established (spot-check
  a few — e.g. confirm `manar-web`'s policy doesn't grant it egress to
  Postgres, which it should never need directly).
- Gitleaks scan of full repo history is clean (or any findings are
  triaged/documented, not silently ignored).
- Trivy/Semgrep run successfully in CI and produce a report artifact.

## Docs

`docs/kubernetes.md` (Section 87) — the chart layout, how to (later,
separately) actually deploy, and the NetworkPolicy design.

## Out of scope this phase

- Actual deployment to any cluster, the production domain, DNS, or production
  Nginx/TLS configuration — explicitly forbidden until a separate,
  later, explicitly-requested deployment phase
- Application-level hardening (Phase 12a — separate, parallel-safe
  workstream)
