# Multi-language test web server for HTTP client integration tests
# This server provides endpoints for testing HTTP clients across all languages
FROM node:18-alpine

WORKDIR /app

# Install dependencies for test server
COPY package.json package-lock.json ./
RUN npm ci --only=production

# Copy test server source
COPY test-server/ ./

# Create SSL certificates for HTTPS testing
RUN apk add --no-cache openssl curl && \
    mkdir -p /app/certs && \
    openssl req -x509 -newkey rsa:4096 -keyout /app/certs/key.pem -out /app/certs/cert.pem \
    -days 365 -nodes -subj "/C=US/ST=CA/L=SF/O=CoyoteSense/CN=test-server"

# Expose ports for HTTP and HTTPS
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start the test server
CMD ["node", "server.js"]
