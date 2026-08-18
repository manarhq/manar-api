# syntax=docker/dockerfile:1

# ---- Base: pnpm-enabled Node image shared by the build stages ----
FROM node:24-alpine AS base
RUN npm install --global pnpm@11.20.0
WORKDIR /app

# ---- deps: install the full dependency graph (dev + prod) for building ----
# --ignore-scripts: no .git directory exists in the build context, so the
# "prepare" (husky) lifecycle script has nothing to install hooks into.
FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts

# ---- build: compile TypeScript -> dist/ ----
FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN pnpm build

# ---- prod-deps: install production-only dependencies ----
FROM base AS prod-deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --prod --ignore-scripts

# ---- runtime: minimal image, no build toolchain, non-root user ----
FROM node:24-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

RUN addgroup --system --gid 1001 nodejs \
  && adduser --system --uid 1001 --ingroup nodejs manar

COPY --from=prod-deps --chown=manar:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=manar:nodejs /app/dist ./dist
COPY --chown=manar:nodejs package.json ./

USER manar

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||3000)+'/health/live',res=>{process.exit(res.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "dist/main.js"]
