###############################################################################
# Stage 1 — Build frontend (Vite) + server (esbuild)
###############################################################################
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Prune to production deps only (these are the "external" deps esbuild didn't bundle)
RUN npm ci --omit=dev

###############################################################################
# Stage 2 — Production runtime
###############################################################################
FROM node:20-alpine AS runtime

RUN apk add --no-cache tini

WORKDIR /app

# Production node_modules (external deps not bundled by esbuild)
COPY --from=builder /app/node_modules ./node_modules

# Built artifacts
COPY --from=builder /app/dist ./dist

# Pre-compiled Go agent binaries for download endpoint
# Code looks at public/agents/ (relative to cwd), so place them there
COPY public/agents ./public/agents

# Drizzle config + schema (needed for db:push migrations)
COPY drizzle.config.ts tsconfig.json ./
COPY shared ./shared
COPY migrations ./migrations

# package.json needed at runtime
COPY package.json ./

ENV NODE_ENV=production
ENV PORT=5000

EXPOSE 5000

# Use tini as init to handle signals properly
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.cjs"]
