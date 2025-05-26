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
COPY tests/integration/CMakeLists.txt ./
COPY tests/integration/cpp/ ./cpp/
COPY factory/ ./factory/
COPY modes/ ./modes/
COPY interfaces/ ./interfaces/

# Build integration tests
RUN mkdir -p build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

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
COPY --from=builder /workspace/build/ ./

# Create results directory
RUN mkdir -p /test-results

# Set environment variables for tests
ENV TEST_SERVER_HOST=test-server
ENV TEST_SERVER_HTTP_PORT=3001
ENV COYOTE_RUNTIME_MODE=production

# Default command runs the integration tests
CMD ["./integration_tests"]
