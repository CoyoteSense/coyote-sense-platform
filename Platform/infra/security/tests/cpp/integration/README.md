# C++ OAuth2 Integration Testing Guide

## Overview

This guide describes how to set up and run C++ OAuth2 integration tests against a real OAuth2 server using the CoyoteSense platform infrastructure.

## Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows (with WSL)
- **C++ Compiler**: GCC 7+ or Clang 10+
- **CMake**: Version 3.16 or higher
- **Docker**: For running the OAuth2 server

### Required Libraries
- **GoogleTest**: For unit testing framework
- **libcurl**: For HTTP client functionality
- **nlohmann/json**: For JSON parsing
- **pkg-config**: For library dependency management

## Quick Start

### 1. Start OAuth2 Server

```bash
# From the tests directory
./manage-oauth2-server.sh start

# Or using PowerShell on Windows
.\manage-oauth2-server.ps1 start
```

### 2. Verify Server Setup

```bash
# Quick validation using Python script
cd cpp/integration
python3 test_oauth2_setup.py
```

### 3. Build and Run C++ Tests

```bash
# Using the provided scripts
./run-cpp-integration-tests.sh

# Or manually
cd cpp/integration
mkdir build && cd build
cmake ..
make
./real_oauth2_integration_test
```

## Detailed Setup

### Installing Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libgtest-dev \
    libcurl4-openssl-dev \
    nlohmann-json3-dev \
    pkg-config
```

#### CentOS/RHEL
```bash
sudo yum install -y \
    gcc-c++ \
    cmake \
    gtest-devel \
    libcurl-devel \
    json-devel \
    pkgconfig
```

#### macOS
```bash
brew install cmake googletest curl nlohmann-json pkg-config
```

#### Windows (using vcpkg)
```bash
vcpkg install gtest:x64-windows
vcpkg install curl:x64-windows
vcpkg install nlohmann-json:x64-windows
```

### OAuth2 Server Configuration

The integration tests use a Docker-based OAuth2 server with the following configuration:

- **Server URL**: `http://localhost:8081`
- **Client ID**: `test-client`
- **Client Secret**: `test-secret`
- **Supported Scopes**: `read write`
- **Grant Types**: `client_credentials`

#### Environment Variables

You can customize the OAuth2 server configuration using environment variables:

```bash
export OAUTH2_SERVER_URL="http://localhost:8081"
export OAUTH2_CLIENT_ID="test-client"
export OAUTH2_CLIENT_SECRET="test-secret"
export OAUTH2_SCOPE="read write"
```

## Test Structure

### Integration Test File

The main integration test file is `real_oauth2_integration_test.cpp` which contains:

1. **Server Connectivity Tests**
   - Verifies OAuth2 server is reachable
   - Tests discovery endpoint (`.well-known/oauth2`)

2. **Authentication Flow Tests**
   - Client credentials grant flow
   - Token introspection
   - Invalid credentials handling

3. **Performance Tests**
   - Multiple concurrent token requests
   - Response time measurements

### Test Classes

#### `SimpleHttpClient`
- Lightweight HTTP client using libcurl
- Supports GET and POST requests
- Handles OAuth2 server communication

#### `RealOAuth2IntegrationTest`
- Main test fixture inheriting from `::testing::Test`
- Sets up OAuth2 server connection
- Provides utility methods for testing

## Running Tests

### Method 1: Using Build Scripts

```bash
# Linux/macOS
./run-cpp-integration-tests.sh

# Windows PowerShell
.\run-cpp-integration-tests.ps1
```

### Method 2: Using CMake

```bash
cd cpp/integration
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build . --config Debug
ctest --verbose
```

### Method 3: Using Make

```bash
cd cpp/integration
make all
make test
```

### Method 4: Direct Execution

```bash
cd cpp/integration/build
export OAUTH2_SERVER_URL="http://localhost:8081"
export OAUTH2_CLIENT_ID="test-client"
export OAUTH2_CLIENT_SECRET="test-secret"
./real_oauth2_integration_test
```

## Test Scenarios

### 1. Server Connectivity Test
```cpp
TEST_F(RealOAuth2IntegrationTest, ServerConnection_ShouldBeReachable)
```
- Verifies OAuth2 server is running
- Checks discovery endpoint response
- Validates server configuration

### 2. Client Credentials Flow Test
```cpp
TEST_F(RealOAuth2IntegrationTest, ClientCredentialsFlow_ShouldAuthenticateSuccessfully)
```
- Tests complete client credentials grant flow
- Verifies token response structure
- Validates access token properties

### 3. Token Introspection Test
```cpp
TEST_F(RealOAuth2IntegrationTest, TokenIntrospection_WithValidToken_ShouldReturnActive)
```
- Tests token introspection endpoint
- Verifies token validity
- Checks introspection response format

### 4. Invalid Credentials Test
```cpp
TEST_F(RealOAuth2IntegrationTest, InvalidClientCredentials_ShouldReturnError)
```
- Tests error handling for invalid credentials
- Verifies proper error response format
- Validates HTTP status codes

### 5. Discovery Endpoint Test
```cpp
TEST_F(RealOAuth2IntegrationTest, DiscoveryEndpoint_ShouldReturnValidConfiguration)
```
- Tests OAuth2 discovery endpoint
- Verifies configuration structure
- Validates endpoint URLs

### 6. Performance Test
```cpp
TEST_F(RealOAuth2IntegrationTest, PerformanceTest_MultipleTokenRequests_ShouldHandleLoad)
```
- Tests server performance under load
- Measures response times
- Validates concurrent request handling

## Expected Output

When tests run successfully, you should see output similar to:

```
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from RealOAuth2IntegrationTest
[ RUN      ] RealOAuth2IntegrationTest.ServerConnection_ShouldBeReachable
✓ OAuth2 server is reachable at http://localhost:8081
[       OK ] RealOAuth2IntegrationTest.ServerConnection_ShouldBeReachable (15 ms)
[ RUN      ] RealOAuth2IntegrationTest.ClientCredentialsFlow_ShouldAuthenticateSuccessfully
✓ Client credentials flow successful
✓ Access token received (length: 205)
[       OK ] RealOAuth2IntegrationTest.ClientCredentialsFlow_ShouldAuthenticateSuccessfully (25 ms)
[----------] 6 tests from RealOAuth2IntegrationTest (150 ms total)
[==========] 6 tests from 1 test suite ran. (150 ms total)
[  PASSED  ] 6 tests.
```

## Troubleshooting

### Common Issues

#### 1. OAuth2 Server Not Running
```
[ERROR] OAuth2 server is not available
```
**Solution**: Start the OAuth2 server using the management scripts.

#### 2. Build Dependencies Missing
```
[ERROR] CMake configuration failed
```
**Solution**: Install required dependencies using package manager.

#### 3. Library Not Found
```
fatal error: gtest/gtest.h: No such file or directory
```
**Solution**: Install GoogleTest development packages.

#### 4. Connection Timeout
```
[ERROR] Failed to connect to server: Connection timed out
```
**Solution**: Check if Docker is running and OAuth2 server is accessible.

### Debug Tips

1. **Check Server Status**:
   ```bash
   curl -v http://localhost:8081/.well-known/oauth2
   ```

2. **Verify Dependencies**:
   ```bash
   pkg-config --modversion libcurl
   ```

3. **Run with Verbose Output**:
   ```bash
   ./real_oauth2_integration_test --gtest_output=xml:results.xml
   ```

4. **Check Docker Logs**:
   ```bash
   docker-compose -f docker-compose.oauth2.yml logs oauth2-server
   ```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: C++ OAuth2 Integration Tests

on: [push, pull_request]

jobs:
  integration-test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential cmake libgtest-dev libcurl4-openssl-dev nlohmann-json3-dev pkg-config
    
    - name: Start OAuth2 server
      run: |
        cd Platform/infra/security/tests
        ./manage-oauth2-server.sh start
    
    - name: Run C++ integration tests
      run: |
        cd Platform/infra/security/tests
        ./run-cpp-integration-tests.sh
```

## Performance Considerations

- **Concurrent Tests**: Tests are designed to run concurrently
- **Timeout Settings**: Default timeout is 10 seconds per request
- **Resource Usage**: Each test uses minimal system resources
- **Server Load**: Performance test simulates realistic load

## Extension Points

### Adding New Tests

1. Create new test methods in the `RealOAuth2IntegrationTest` class
2. Follow the naming convention: `TestName_WithCondition_ShouldExpectedOutcome`
3. Use the provided utility methods for server communication
4. Include appropriate assertions and logging

### Custom OAuth2 Flows

The test framework can be extended to support additional OAuth2 flows:

- Authorization Code Grant
- Resource Owner Password Credentials
- JWT Bearer Token Grant
- Device Authorization Grant

## Security Considerations

- Tests use a dedicated test OAuth2 server
- No production credentials are used
- All test data is ephemeral
- Network traffic is unencrypted (test environment only)

## Maintenance

### Updating Dependencies

Regularly update the required libraries:

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get upgrade

# macOS
brew update && brew upgrade
```

### Version Compatibility

- **C++ Standard**: Tests require C++17 or later
- **GoogleTest**: Compatible with versions 1.10+
- **libcurl**: Compatible with versions 7.0+
- **nlohmann/json**: Compatible with versions 3.0+

This integration test suite provides comprehensive coverage of OAuth2 functionality and ensures that the C++ components work correctly with real OAuth2 servers.
