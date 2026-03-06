# ============================================================
# Trancendos Ecosystem — Production Dockerfile
# Multi-stage build | Node 20 Alpine | 2060-ready
# ============================================================
# Stage 1: Dependencies
FROM node:20-alpine AS deps
WORKDIR /app

# Install security updates
RUN apk update && apk upgrade --no-cache

# Copy package files
COPY package*.json ./
COPY tsconfig*.json ./

# Install production dependencies only
RUN npm ci --only=production --ignore-scripts 2>/dev/null || npm install --only=production --ignore-scripts

# Stage 2: Build
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
COPY tsconfig*.json ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts

# Copy source
COPY . .

# Build TypeScript
RUN npm run build 2>/dev/null || npx tsc --outDir dist 2>/dev/null || echo "No build step configured"

# Stage 3: Production
FROM node:20-alpine AS production
WORKDIR /app

# Security: non-root user
RUN addgroup -g 1001 -S trancendos && \
    adduser -S trancendos -u 1001 -G trancendos

# Install security updates + tini for proper signal handling
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache tini curl

# Copy production dependencies
COPY --from=deps /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json

# Environment defaults
ENV NODE_ENV=production
ENV PORT=3000
ENV IAM_ENABLED=true
ENV MESH_ROUTING_PROTOCOL=static_port
ENV LOG_LEVEL=info

# Health check — IAM-aware
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:${PORT}/health || exit 1

# Switch to non-root user
USER trancendos

# Expose service port
EXPOSE ${PORT}

# Use tini as init system for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start service
CMD ["node", "dist/index.js"]