#
# Build context for this Dockerfile is the REPO ROOT (see
# deploy/docker-compose.yml's `demo-soc-tools` service: `context: ..`),
# not this directory — this package lives in manar-api's pnpm workspace
# and shares the root pnpm-lock.yaml, so `pnpm install --frozen-lockfile`
# needs to run against the whole workspace. `--filter` below then scopes
# the actual install/build to just this package; the sibling
# packages/sdk-node and the main manar-api Nest app are never built into
# this image. Mirrors the multi-stage/non-root/HEALTHCHECK conventions of
# the root Dockerfile (manar-api's own).

# ---- Base: pnpm-enabled Node image shared by the build stages ----
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS base
RUN npm install --global pnpm@11.20.0
WORKDIR /app

# ---- deps: install this package's dependency graph (dev + prod) ----
# Only manifests are copied in (no source) — pnpm's frozen-lockfile
# install needs every workspace package's package.json present to resolve
# the graph the lockfile describes, but packages/sdk-node's *source* is
# irrelevant to this image and deliberately left out.
FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/sdk-node/package.json ./packages/sdk-node/package.json
COPY packages/demo-soc-tools/package.json ./packages/demo-soc-tools/package.json
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @manar/demo-soc-tools...

# ---- build: compile TypeScript -> dist/ ----
# `pnpm --filter` needs the root workspace manifests present (not just
# node_modules) to resolve the workspace it's filtering, hence copying
# package.json/pnpm-lock.yaml/pnpm-workspace.yaml again here too.
FROM base AS build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/sdk-node/package.json ./packages/sdk-node/package.json
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/demo-soc-tools/node_modules ./packages/demo-soc-tools/node_modules
COPY packages/demo-soc-tools ./packages/demo-soc-tools
RUN pnpm --filter @manar/demo-soc-tools build

# ---- prod-deps: install production-only dependencies for this package ----
FROM base AS prod-deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/sdk-node/package.json ./packages/sdk-node/package.json
COPY packages/demo-soc-tools/package.json ./packages/demo-soc-tools/package.json
RUN pnpm install --frozen-lockfile --prod --ignore-scripts --filter @manar/demo-soc-tools...

# ---- runtime: minimal image, no build toolchain, non-root user ----
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS runtime
ENV NODE_ENV=production
WORKDIR /app

RUN addgroup --system --gid 1001 nodejs \
  && adduser --system --uid 1001 --ingroup nodejs demosoc

# The runtime only runs `node`; the base image's bundled npm, corepack and
# yarn (and their dependencies' advisories in image scans) are build tools.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
  /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
  /opt/yarn-v* /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY --from=prod-deps --chown=demosoc:nodejs /app/node_modules ./node_modules
COPY --from=prod-deps --chown=demosoc:nodejs /app/packages/demo-soc-tools/node_modules ./packages/demo-soc-tools/node_modules
COPY --from=build --chown=demosoc:nodejs /app/packages/demo-soc-tools/dist ./packages/demo-soc-tools/dist
COPY --chown=demosoc:nodejs packages/demo-soc-tools/package.json ./packages/demo-soc-tools/package.json

USER demosoc

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||3100)+'/health/live',res=>{process.exit(res.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "packages/demo-soc-tools/dist/main.js"]
