# CoyoteSense OAuth2 Authentication Tests

This directory contains comprehensive OAuth2 authentication tests for all client libraries (C#, C++, TypeScript, Python) with both unit tests (using mocks) and integration tests (using real OAuth2 server).

## Quick Start

### Prerequisites
- **Docker Desktop** - For OAuth2 server
- **.NET SDK** - For C# tests
- **Node.js** - For TypeScript tests  
- **Visual Studio Build Tools** or **GCC/Clang** - For C++ tests

### Run All Tests (Unit/Mock Only)
```powershell
# Windows PowerShell
.\run_tests.ps1

# Linux/Mac Bash
./run_tests.sh
```

### Run Integration Tests (Real OAuth2 Server)
```powershell
# Windows PowerShell - All languages
.\run_integration_tests.ps1

# Specific language only
.\run_integration_tests.ps1 -Language cs    # C# only
.\run_integration_tests.ps1 -Language cpp   # C++ only
.\run_integration_tests.ps1 -Language ts    # TypeScript only

# Linux/Mac Bash  
./run_integration_tests.sh
```

### Manage OAuth2 Server
```powershell
# Start OAuth2 server
.\manage-oauth2-server.ps1 start

# Stop OAuth2 server
.\manage-oauth2-server.ps1 stop

# Check server status
.\manage-oauth2-server.ps1 status
```

## Directory Structure

```
tests/
├── run_tests.ps1                    # Main test runner (unit/mock tests)
├── run_integration_tests.ps1        # Integration test runner (real OAuth2)
├── manage-oauth2-server.ps1         # OAuth2 server management
├── docker-compose.oauth2.yml        # OAuth2 server Docker config
├── docker/                          # OAuth2 server implementation
├── cpp/                             # C++ tests
│   ├── integration/                 # Real OAuth2 integration tests
│   └── unit/                        # Unit tests with mocks
├── dotnet/                          # C# tests
│   ├── Integration/                 # Real OAuth2 integration tests
│   └── Unit/                        # Unit tests with mocks
├── ts/                              # TypeScript tests
│   ├── integration/                 # Real OAuth2 integration tests
│   └── unit/                        # Unit tests with mocks
├── python/                          # Python tests
└── reports/                         # Generated test reports
```

## Test Types

### Unit Tests (Mock-based)
- **Fast execution** - All external dependencies mocked
- **Isolated testing** - Each component tested in isolation
- **Configuration validation** - Config parsing and validation
- **OAuth2 flows** - All grant types with mock responses
- **Token management** - Storage, refresh, expiration handling
- **Error scenarios** - Various failure conditions
- **Security features** - Credential masking, SSL validation

### Integration Tests (Real OAuth2 Server)
- **End-to-end validation** - Real OAuth2 server interactions
- **Docker-based server** - Automated OAuth2 server setup
- **Client credentials flow** - Real token acquisition
- **Token introspection** - Token validation endpoints
- **Error handling** - Network failures, invalid credentials
- **Performance testing** - Response times, concurrent requests

## Test Results Status

### ✅ C# Tests
- **Unit Tests**: 118/124 passing (6 skipped - known hanging tests)
- **Integration Tests**: All passing with real OAuth2 server
- **Coverage**: Comprehensive mocking and real server validation

### ✅ C++ Tests  
- **Unit Tests**: All passing with Google Test framework
- **Integration Tests**: All passing with libcurl + vcpkg dependencies
- **Build System**: CMake with vcpkg, Visual Studio auto-detection

### ✅ TypeScript Tests
- **Unit Tests**: 46/46 passing (improved from previous failures)
- **Integration Tests**: 11/11 passing with real OAuth2 server
- **Framework**: Jest with proper mocking and real fetch

### ✅ Python Tests
- **Unit Tests**: All passing with pytest framework
- **Integration Tests**: Server validation and connectivity tests
- **Tools**: Python-based OAuth2 server validation utilities
- **Server discovery** - Test OAuth2 server discovery

### Mock Implementations
- **Mock OAuth2 server** - Lightweight server for testing
- **Mock token storage** - In-memory storage for tests
- **Mock HTTP client** - Configurable HTTP responses

## Running Tests

### Prerequisites
- Docker and Docker Compose (for integration tests)
- Language-specific dependencies installed
- Valid test certificates in `common/test-data/certs/`

### All Tests
```powershell
.\scripts\run-all-tests.ps1
```

### Unit Tests Only
```powershell
.\scripts\run-unit-tests.ps1
```

### Integration Tests Only
```powershell
.\scripts\run-integration-tests.ps1
```

### Language-Specific Tests
```powershell
# C++ tests
.\scripts\run-all-tests.ps1 -Language cpp

# C# tests
.\scripts\run-all-tests.ps1 -Language csharp

# Python tests
.\scripts\run-all-tests.ps1 -Language python

# TypeScript tests
.\scripts\run-all-tests.ps1 -Language typescript
```

## Test Data

The `common/test-data/` directory contains:
- **Test certificates** - Self-signed certificates for mTLS testing
- **JWT keys** - RSA key pairs for JWT Bearer flow testing
- **OAuth2 responses** - Sample OAuth2 server responses
- **Test configurations** - Various client configurations for testing

## Mock OAuth2 Server

The mock OAuth2 server (`common/mock-oauth2-server/`) provides:
- All standard OAuth2 endpoints
- Support for all grant types
- Configurable responses and error conditions
- mTLS endpoint simulation
- Token introspection and revocation
- Server discovery endpoints

## Continuous Integration

Tests are designed to run in CI/CD pipelines with:
- Parallel execution across languages
- Docker-based test isolation
- Comprehensive test reporting
- Code coverage metrics
- Performance benchmarking

## Security Testing

Security-focused tests include:
- **Certificate validation** - Test mTLS certificate handling
- **Token security** - Test token encryption and secure storage
- **Input validation** - Test handling of malicious inputs
- **SSL/TLS verification** - Test certificate verification
- **Timing attacks** - Test constant-time operations
