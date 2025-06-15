# Multi-stage Dockerfile for C++ HTTP Client Integration Tests

# Stage 1: Build environment
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    nlohmann-json3-dev \
    pkg-config \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download and build Google Test from source
RUN cd /tmp && \
    git clone https://github.com/google/googletest.git && \
    cd googletest && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) && \
    make install

# Set work directory
WORKDIR /workspace

# Copy the project files needed for tests
COPY tests/integration/CMakeLists.txt ./tests/integration/
COPY tests/integration/cpp/ ./tests/integration/cpp/
COPY src/cpp/factory/ ./src/cpp/factory/
COPY src/cpp/impl/ ./src/cpp/impl/
COPY src/cpp/interfaces/ ./src/cpp/interfaces/

# Build integration tests
RUN mkdir -p build && cd build && \
    cmake ../tests/integration \
        -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    echo "Files in build directory:" && \
    ls -la && \
    echo "Files in build directory (find all):" && \
    find . -type f | sort

# Stage 2: Runtime environment
FROM ubuntu:22.04 AS runtime

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libcurl4 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy built binaries from builder stage
COPY --from=builder /workspace/build/integration_tests ./
COPY --from=builder /workspace/build/libintegration_tests.* ./

# List files to see what's available
RUN ls -la

# Create results directory
RUN mkdir -p /test-results

# Set environment variables for tests
ENV TEST_SERVER_HOST=test-server
ENV TEST_SERVER_HTTP_PORT=8080
ENV TEST_SERVER_HTTPS_PORT=8443
ENV COYOTE_RUNTIME_MODE=production

# Debug: Add a health check to verify test server is reachable
RUN echo "#!/bin/sh\ncurl -f http://\$TEST_SERVER_HOST:\$TEST_SERVER_HTTP_PORT/health || exit 1" > /app/healthcheck.sh && \
    chmod +x /app/healthcheck.sh

# Default command runs the integration tests
CMD ["./integration_tests"]
