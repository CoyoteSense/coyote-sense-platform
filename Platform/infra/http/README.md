# Coyote HTTP Client Infrastructure

This directory contains the C++ implementation of the HTTP client infrastructure for the Coyote Sense Platform, following the runtime modes pattern described in the platform documentation.

## Overview

The HTTP client infrastructure provides a mode-aware HTTP client that can switch between different implementations based on the `COYOTE_RUNTIME_MODE` environment variable or `MODE` environment variable.

## Architecture

```
infra/http/cpp/
├── interfaces/cpp/          # Pure interfaces
│   └── http_client.h       # HttpClient, HttpRequest, HttpResponse
├── factory/cpp/            # Factory for mode selection
│   ├── http_client_factory.h
│   └── http_client_factory.cpp
├── modes/                  # Mode-specific implementations
│   ├── real/cpp/          # Production HTTP client using CURL
│   │   ├── http_client_real.h
│   │   └── http_client_real.cpp
│   └── mock/cpp/          # Mock client for testing
│       ├── http_client_mock.h
│       └── http_client_mock.cpp
└── examples/              # Usage examples
    └── http_client_example.cpp
```

## Runtime Modes

| Mode | Implementation | Description |
|------|----------------|-------------|
| `production` | `HttpClientReal` | Real HTTP client using libcurl |
| `recording` | `HttpClientReal` | Real HTTP client (same as production) |
| `replay` | `HttpClientReal` | Real HTTP client (same as production) |
| `simulation` | `HttpClientReal` | Real HTTP client (same as production) |
| `debug` | `HttpClientReal` | Real HTTP client (same as production) |
| `testing` | `HttpClientMock` | Mock client for unit tests |

## Usage

### Basic Usage

```cpp
#include <coyote/http/http_client_factory.h>

// Create client based on current runtime mode
auto client = coyote::infra::MakeHttpClient();

// Make requests
auto response = client->Get("https://api.example.com/data");
if (response->IsSuccess()) {
    std::cout << "Response: " << response->GetBody() << std::endl;
}
```

### Explicit Mode Selection

```cpp
#include <coyote/http/http_client_factory.h>

// Create client for specific mode
auto client = coyote::infra::HttpClientFactory::CreateHttpClient(
    coyote::infra::RuntimeMode::kProduction
);
```

### Configuration

```cpp
// Configure default settings
client->SetDefaultTimeout(10000);  // 10 seconds
client->SetDefaultHeaders({
    {"User-Agent", "CoyoteSense/1.0"},
    {"Accept", "application/json"}
});

// SSL/TLS configuration
client->SetClientCertificate("/path/to/cert.pem", "/path/to/key.pem");
client->SetCACertificate("/path/to/ca.pem");
client->SetVerifyPeer(true);
```

### HTTP Methods

```cpp
// GET request
auto response = client->Get("https://api.example.com/users");

// POST request
auto response = client->Post(
    "https://api.example.com/users", 
    R"({"name": "John", "email": "john@example.com"})",
    {{"Content-Type", "application/json"}}
);

// PUT request
auto response = client->Put(
    "https://api.example.com/users/123",
    R"({"name": "John Updated"})",
    {{"Content-Type", "application/json"}}
);

// DELETE request
auto response = client->Delete("https://api.example.com/users/123");
```

### Custom Requests

```cpp
#include "modes/real/cpp/http_client_real.h"

coyote::infra::HttpRequestReal request;
request.SetUrl("https://api.example.com/custom");
request.SetMethod(coyote::infra::HttpMethod::kPatch);
request.SetBody(R"({"operation": "update"})");
request.SetHeader("Content-Type", "application/json");
request.SetTimeout(5000);

auto response = client->Execute(request);
```

## Testing with Mock Client

```cpp
#include "modes/mock/cpp/http_client_mock.h"

// Create mock client
auto mock_client = std::make_unique<coyote::infra::mocks::HttpClientMock>();

// Set up mock response
coyote::infra::mocks::RequestMatcher matcher;
matcher.url_pattern = ".*api/users.*";
matcher.method = coyote::infra::HttpMethod::kGet;

auto mock_response = std::make_unique<coyote::infra::mocks::MockHttpResponse>(
    200, 
    R"([{"id": 1, "name": "Test User"}])",
    {{"content-type", "application/json"}}
);

mock_client->SetMockResponse(matcher, std::move(mock_response));

// Use the mock
auto response = mock_client->Get("https://api.example.com/users");
assert(response->GetStatusCode() == 200);

// Verify request history
assert(mock_client->GetRequestCount() == 1);
```

## Dependencies

- **libcurl**: Required for the real HTTP client implementation
- **C++17**: Minimum C++ standard
- **CMake 3.16+**: For building

## Building

```bash
mkdir build && cd build
cmake ..
make
```

### With Examples

```bash
cmake -DBUILD_HTTP_CLIENT_EXAMPLES=ON ..
make
./http_client_example
```

## Environment Variables

- `MODE` or `COYOTE_RUNTIME_MODE`: Sets the runtime mode
- `CURL_VERBOSE`: Enable verbose CURL output for debugging

## Error Handling

All HTTP operations return `std::unique_ptr<HttpResponse>`. Check the response:

```cpp
auto response = client->Get("https://api.example.com/data");

if (response->IsSuccess()) {
    // Status code 200-299
    std::cout << "Success: " << response->GetBody() << std::endl;
} else {
    std::cerr << "HTTP Error " << response->GetStatusCode() 
              << ": " << response->GetErrorMessage() << std::endl;
}
```

## Google C++ Style Guidelines

This implementation follows Google C++ Style Guidelines:

- Class names: `PascalCase` (e.g., `HttpClientReal`)
- Method names: `PascalCase` (e.g., `SetDefaultTimeout`)
- Member variables: `snake_case_` with trailing underscore
- Constants: `kConstantName`
- Namespaces: `snake_case`

## Thread Safety

- `HttpClientReal`: Thread-safe for concurrent requests
- `HttpClientMock`: Thread-safe with internal mutex protection
- Factory methods: Thread-safe

## Performance Considerations

- The real HTTP client reuses CURL handles for better performance
- Mock client has minimal overhead for testing scenarios
- Default timeout is 10 seconds, adjust as needed for your use case

## Testing

The C++ HTTP client infrastructure includes comprehensive testing capabilities with both unit tests and integration tests.

### Test Architecture

```
tests/
├── unit/                          # Unit tests
│   ├── CMakeLists.txt            # Unit test build configuration
│   ├── test_http_client_mock.cpp # Mock client unit tests
│   └── test_http_client_factory.cpp # Factory unit tests
└── integration/                   # Integration tests
    ├── CMakeLists.txt            # Integration test build
    ├── docker-compose.yml        # Docker test environment
    ├── run-integration-tests.sh  # Test runner script
    ├── run-integration-tests.ps1 # Windows test runner
    ├── cpp/                      # C++ integration tests
    │   ├── test_http_client_integration.cpp
    │   └── common/
    │       ├── test_helpers.h
    │       └── test_helpers.cpp
    ├── test-server/              # Node.js test web server
    │   └── server.js
    ├── test-server.Dockerfile    # Test server container
    └── cpp-tests.Dockerfile      # C++ test container
```

### Unit Tests

Unit tests focus on testing individual components in isolation:

```bash
# Build with unit tests
mkdir build && cd build
cmake -DBUILD_HTTP_CLIENT_TESTS=ON ..
cmake --build .

# Run unit tests
ctest --output-on-failure
# or directly
./tests/unit/http_client_unit_tests
```

**Unit Test Coverage:**
- Mock HTTP client functionality
- Request/response handling
- Factory pattern and mode selection
- Thread safety
- Error handling
- Configuration management

### Integration Tests

Integration tests validate the HTTP client against a real web server using Docker:

```bash
# Prerequisites: Docker and Docker Compose

# Run integration tests (Linux/macOS)
cd tests/integration
./run-integration-tests.sh

# Run integration tests (Windows)
cd tests/integration
.\run-integration-tests.ps1
```

**Integration Test Coverage:**
- Real HTTP requests (GET, POST, PUT, DELETE)
- Various status codes (200, 400, 401, 404, 500)
- Request/response headers
- JSON handling
- Authentication (Bearer tokens)
- Large response handling
- Network timeouts
- SSL/TLS configuration
- Error scenarios

### Test Server

The integration tests use a comprehensive Node.js test server that provides:

- **Health Check**: `GET /health`
- **HTTP Methods**: All standard HTTP methods
- **Status Codes**: `GET /api/status/{code}` - returns any status code
- **Headers**: `GET /api/headers` - echoes request headers
- **JSON**: `GET /api/json` - returns structured JSON data
- **Authentication**: `GET /api/auth/bearer` - Bearer token validation
- **Large Responses**: `GET /api/large/{size_kb}` - configurable response sizes
- **Timeouts**: `GET /api/timeout/{seconds}` - configurable delays
- **HTTPS Support**: SSL/TLS endpoints on port 8443

### Docker-Based Testing

The integration test environment uses Docker containers:

1. **Test Server Container**: Node.js server with all test endpoints
2. **C++ Test Container**: Builds and runs C++ integration tests
3. **Network Isolation**: Tests run in isolated Docker network
4. **SSL Certificates**: Self-signed certificates for HTTPS testing

### Running Specific Test Types

```bash
# Unit tests only
cmake -DBUILD_HTTP_CLIENT_TESTS=ON -DBUILD_INTEGRATION_TESTS=OFF ..
make && ctest

# Integration tests only
cd tests/integration
./run-integration-tests.sh --test-only

# Build test images only
./run-integration-tests.sh --build-only

# Start test server for manual testing
./run-integration-tests.sh --server-only
# Server available at http://localhost:8080 and https://localhost:8443
```

### Test Configuration

Tests support various configuration options via environment variables:

```bash
# Runtime mode selection
export COYOTE_RUNTIME_MODE=production  # Use real HTTP client
export COYOTE_RUNTIME_MODE=testing     # Use mock HTTP client

# Test server configuration
export TEST_SERVER_HOST=localhost
export TEST_SERVER_HTTP_PORT=8080
export TEST_SERVER_HTTPS_PORT=8443

# CURL debugging
export CURL_VERBOSE=1  # Enable verbose CURL output
```

### Windows Testing Notes

On Windows without libcurl:
- Unit tests run normally (use mock client)
- Integration tests are skipped automatically
- Example gracefully handles missing CURL
- Factory returns mock client for production mode

To enable full testing on Windows:
```bash
# Install libcurl via vcpkg
vcpkg install curl
cmake -DCMAKE_TOOLCHAIN_FILE=path/to/vcpkg.cmake ..
```

### Continuous Integration

For CI/CD pipelines:

```bash
# Complete test suite
cmake -DBUILD_HTTP_CLIENT_TESTS=ON -DBUILD_INTEGRATION_TESTS=ON ..
make
ctest --output-on-failure

# Integration tests in CI
cd tests/integration
./run-integration-tests.sh --clean
```

### Test Helpers

The integration tests include utility functions:

```cpp
#include "test_helpers.h"

// Environment variable management
test_helpers::SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "production");
std::string mode = test_helpers::GetEnvironmentVariable("MODE", "testing");

// Network utilities
bool server_ready = test_helpers::WaitForPort("localhost", 8080, 30);
bool port_open = test_helpers::IsPortOpen("localhost", 8080);

// Test data generation
std::string random_data = test_helpers::GenerateRandomString(100);
std::string encoded = test_helpers::UrlEncode("test data");

// JSON parsing (simple)
std::string value = test_helpers::ExtractJsonValue(json_str, "key");
```

### Debugging Tests

Enable verbose output for debugging:

```bash
# Unit tests with verbose output
./http_client_unit_tests --gtest_output=verbose

# Integration tests with server logs
./run-integration-tests.sh --logs

# CURL debugging
export CURL_VERBOSE=1
./integration_tests
```
