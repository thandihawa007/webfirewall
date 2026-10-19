# Multi-stage Dockerfile for Droplet WAF & Reverse Proxy
FROM node:20-alpine AS builder

WORKDIR /app

# Install native compile dependencies for better-sqlite3 and bcrypt
RUN apk add --no-cache python3 make g++ sqlite-dev

COPY package*.json ./
RUN npm ci

COPY . .

# Production Runner Stage
FROM node:20-alpine AS runner

WORKDIR /app

RUN apk add --no-cache sqlite-libs

ENV NODE_ENV=production
ENV PORT=3000
ENV DB_PATH=/app/data/droplet.db

# Prepare persistent data directory and grant permissions to node user
RUN mkdir -p /app/data && chown -R node:node /app

COPY --chown=node:node --from=builder /app /app

# Non-root user execution
USER node

EXPOSE 3000

CMD ["node", "server.js"]
