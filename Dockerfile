FROM node:20-alpine

# Install Lua
RUN apk add --no-cache lua5.1 lua5.1-dev

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy app files
COPY . .

# Create temp directory
RUN mkdir -p /tmp/obfuscator

# Test Prometheus
RUN lua test-prometheus.lua || echo "Warning: Prometheus test failed"

# Expose port (Railway auto-detects)
ENV PORT=3000

# Start bot
CMD ["node", "index.js"]
