# ---- Base: pnpm-enabled Node image shared by the build stages ----
# Debian (glibc), like the runtime stage: @temporalio/core-bridge ships glibc
# builds only, and native modules installed here must match the runtime libc.
FROM node:24-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS base
RUN npm install --global pnpm@11.20.0
WORKDIR /app

# ---- deps: install the full dependency graph (dev + prod) for building ----
# --ignore-scripts: no .git directory exists in the build context, so the
# "prepare" (husky) lifecycle script has nothing to install hooks into.
# Also skips the root "postinstall" (which needs the prisma schema files,
# not copied in yet at this stage) and Prisma's own install scripts; the
# latter are run explicitly below via `pnpm rebuild`, since `prisma
# generate`/`migrate` need @prisma/engines's schema-engine binary.
FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts \
  && pnpm rebuild @prisma/engines prisma

# ---- build: compile TypeScript -> dist/ ----
FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Phase 12b container-hardening audit finding: the root package.json's own
# "build" script (`nest build && pnpm --filter @manar/sdk-node build &&
# pnpm --filter @manar-ai/grpc-client build`) runs `nest build` *before*
# `@manar-ai/grpc-client` — but src/ai-advisory/ai-advisory-client.service.ts
# imports that package's compiled dist/ output (see
# packages/manar-ai-client/package.json's "types" field), so `nest build`'s
# typecheck fails against a clean install with no stale dist/ from a
# previous build to fall back on (reproduces on a bare `pnpm build` too,
# not a Docker-specific issue — pre-existing, not introduced by this
# Dockerfile). Fixing the script ordering itself is package.json/
# application-source territory (out of this phase's scope — see
# docs/kubernetes.md); pre-building the dependency here instead makes this
# image buildable without touching that file. `pnpm build`'s own script
# still redundantly rebuilds both workspace packages afterward — harmless,
# just a few extra idempotent seconds. `@manar/sdk-node` has the same
# problem since the CLI's demo:seed imports it, so build both packages.
RUN pnpm packages:build \
  && pnpm db:generate && pnpm build

# ---- prod-deps: install production-only dependencies ----
# The workspace manifests are copied too, so pnpm links the workspace packages
# dist/ requires at runtime (@manar-ai/grpc-client, and @manar/sdk-node for the
# CLI) and installs their own dependencies. Their dist/ comes from `build`.
# @confluentinc/kafka-javascript's install script fetches its prebuilt native
# binding; --ignore-scripts skipped it, so it is rebuilt with Prisma's.
FROM base AS prod-deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/manar-ai-client/package.json packages/manar-ai-client/
COPY packages/sdk-node/package.json packages/sdk-node/
COPY packages/demo-soc-tools/package.json packages/demo-soc-tools/
RUN pnpm install --frozen-lockfile --prod --ignore-scripts \
  && pnpm rebuild @prisma/engines prisma @confluentinc/kafka-javascript

# ---- runtime: minimal image, no build toolchain, non-root user ----
FROM node:24-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS runtime
ENV NODE_ENV=production
# Reported in the manar-fleet heartbeat (ADR-0010). CI passes the commit sha.
ARG MANAR_GIT_SHA=unknown
ENV MANAR_GIT_SHA=${MANAR_GIT_SHA}
WORKDIR /app

# ca-certificates: the system trust store for native TLS clients (librdkafka, the
# Temporal core bridge, Prisma's schema engine); Node itself uses its bundled roots.
# apt-get upgrade picks up Debian security fixes newer than the base image digest.
RUN apt-get update \
  && apt-get upgrade -y --no-install-recommends \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --system --gid 1001 nodejs \
  && useradd --system --uid 1001 --gid nodejs --no-create-home --shell /usr/sbin/nologin manar

# The runtime only runs `node`; the base image's bundled npm, corepack and
# yarn (and their dependencies' advisories in image scans) are build tools.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
  /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
  /opt/yarn-v* /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY --from=prod-deps --chown=manar:nodejs /app/node_modules ./node_modules
# Workspace packages behind node_modules/@manar-ai/grpc-client and
# node_modules/@manar/sdk-node: manifest, compiled dist/ and their production
# node_modules only (no sources, no dev dependencies).
COPY --from=prod-deps --chown=manar:nodejs /app/packages/manar-ai-client/node_modules ./packages/manar-ai-client/node_modules
COPY --from=build --chown=manar:nodejs /app/packages/manar-ai-client/package.json ./packages/manar-ai-client/
COPY --from=build --chown=manar:nodejs /app/packages/manar-ai-client/dist ./packages/manar-ai-client/dist
COPY --from=prod-deps --chown=manar:nodejs /app/packages/sdk-node/node_modules ./packages/sdk-node/node_modules
COPY --from=build --chown=manar:nodejs /app/packages/sdk-node/package.json ./packages/sdk-node/
COPY --from=build --chown=manar:nodejs /app/packages/sdk-node/dist ./packages/sdk-node/dist
COPY --from=build --chown=manar:nodejs /app/dist ./dist
COPY --chown=manar:nodejs package.json ./
# TenantDatabaseManager.provisionTenant spawns `prisma migrate deploy
# --schema prisma/tenant.prisma --config prisma/tenant.config.ts` as a
# runtime child process (see docs/tenant-isolation.md) — the schema,
# config, and migrations must exist on disk at runtime, not just at build
# time. This does not include src/generated (already compiled into dist).
COPY --chown=manar:nodejs prisma ./prisma
# OpenFgaClientService reads the authorization model DSL from disk at boot
# (OPENFGA_MODEL_FILE_PATH, default src/authorization/model/manar.fga, also
# the Helm default); it is not compiled into dist. Root-owned: the app only reads it.
COPY src/authorization/model/manar.fga ./src/authorization/model/manar.fga

USER manar

# 3000: human-facing REST API (src/main.ts's primary Fastify listener).
# 3443: the agent-facing mTLS HTTPS listener src/main.ts also starts
# (AgentMtlsConfigSchema.AGENT_MTLS_PORT, `/agent/v1/*` — see
# docs/agent-identity.md) — added here during the Phase 12b container
# hardening audit; this stage's own bootstrap has opened this second
# listener since Phase 4, but EXPOSE (documentation only, doesn't gate
# anything at runtime) had drifted and never listed it.
EXPOSE 3000 3443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||3000)+'/health/live',res=>{process.exit(res.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "dist/main.js"]

# ---- worker: identical image, different entrypoint ----
# Phase 8 (Approval Engine): the Temporal worker (src/worker.main.ts) runs
# as its own process, never sharing an event loop with the Fastify HTTP
# server `runtime`'s own CMD starts (Section 28). Rather than a wholly
# separate build (which would duplicate every layer above verbatim), this
# stage is `runtime` with only its CMD replaced — the same artifact, run
# as two different container images/deployments (e.g. one Kubernetes
# Deployment for `runtime`, a second for `worker`) so either can scale,
# restart, and fail independently. This process serves no HTTP endpoint to
# probe (a real deployment would instead use Temporal's own worker-heartbeat
# visibility, or a liveness probe on the process itself — see
# deploy/helm/manar-api-worker/values.yaml's exec livenessProbe).
#
# `HEALTHCHECK NONE` is load-bearing, not decorative: a derived stage
# *inherits* its parent's HEALTHCHECK, so until release 2026-11-11 this
# stage silently kept `runtime`'s HTTP check above — curling
# /health/live on a port nothing in this container listens on. Every worker
# container therefore reported `unhealthy` forever, and any orchestrator
# configured to act on Docker health status (compose `depends_on:
# service_healthy`, a Swarm/ECS health check) would restart-loop a
# perfectly functional worker. The comment here previously claimed there
# was no HEALTHCHECK in this stage; this makes that true.
FROM runtime AS worker
HEALTHCHECK NONE
CMD ["node", "dist/worker.main.js"]
