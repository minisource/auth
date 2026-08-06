# syntax=docker/dockerfile:1

# ── Builder ──────────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /src

ENV NEXT_TELEMETRY_DISABLED=1

# Install dependencies (includes @minisource/ui from npm registry)
COPY package.json ./
RUN npm install --legacy-peer-deps --no-audit --no-fund

# Copy source and build
COPY . .
RUN npm run build

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

WORKDIR /app

COPY --from=builder /src/public ./public
COPY --from=builder /src/.next/standalone ./
COPY --from=builder /src/.next/static ./.next/static

RUN chown -R nextjs:nodejs /app
USER nextjs
EXPOSE 3003

ENV PORT=3003
ENV HOSTNAME=0.0.0.0

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3003/auth/login || exit 1

CMD ["node", "server.js"]
