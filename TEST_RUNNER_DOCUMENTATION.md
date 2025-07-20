# Test Runner Scripts Documentation

This document describes the two main test runner scripts for the CoyoteSense platform OAuth2 integration testing.

## Overview

The platform provides two main test runner scripts to support different testing scenarios:

1. **`run_tests.ps1`** - Runs all tests except real OAuth2 integration tests
2. **`run_integration_tests.ps1`** - Runs real OAuth2 integration tests for all languages

## Script 1: `run_tests.ps1`

### Purpose
Runs all unit tests, mock tests, and other non-integration tests across all supported languages. This script is designed for daily development and CI/CD pipelines where you don't want to start external services.

### Usage
```powershell
# Run all tests for all languages
.\run_tests.ps1

# Run tests for specific language only
.\run_tests.ps1 -Language typescript
.\run_tests.ps1 -Language csharp
.\run_tests.ps1 -Language cpp

# Run with coverage reporting
.\run_tests.ps1 -Coverage

# Run with verbose output
.\run_tests.ps1 -Verbose

# Combine options
.\run_tests.ps1 -Language csharp -Coverage -Verbose
```

### Parameters
- **`-Language`**: Filter tests by language (`csharp`, `cpp`, `typescript`, `all`)
- **`-Coverage`**: Enable coverage reporting where supported
- **`-Verbose`**: Show detailed output from test runs

### What It Tests
- **C#**: Unit tests with mocked OAuth2 endpoints (excludes `Category=RealIntegration`)
- **C++**: Displays available test infrastructure (requires manual build setup)
- **TypeScript**: Unit tests only (excludes integration folder)

### Requirements
- **C#**: .NET SDK
- **TypeScript**: Node.js and npm
- **C++**: Build tools (Visual Studio Build Tools, MinGW, or GCC) for actual testing

### Expected Output
- Lists available test infrastructure for each language
- Runs unit/mock tests that don't require external services
- Provides summary of test results
- Guidance on running integration tests if needed

## Script 2: `run_integration_tests.ps1`

### Purpose
Runs real OAuth2 integration tests against a live OAuth2 server. This script automatically starts a Docker-based OAuth2 server, runs integration tests, and handles cleanup.

### Usage
```powershell
# Run integration tests for all languages
.\run_integration_tests.ps1

# Run for specific language only
.\run_integration_tests.ps1 -Language typescript
.\run_integration_tests.ps1 -Language csharp
.\run_integration_tests.ps1 -Language cpp

# Keep OAuth2 server running after tests
.\run_integration_tests.ps1 -KeepServer

# Start OAuth2 server only (no tests)
.\run_integration_tests.ps1 -ServerOnly

# Run with verbose output
.\run_integration_tests.ps1 -Verbose

# Combine options
.\run_integration_tests.ps1 -Language csharp -KeepServer -Verbose
```

### Parameters
- **`-Language`**: Filter tests by language (`csharp`, `cpp`, `typescript`, `all`)
- **`-KeepServer`**: Keep OAuth2 server running after tests complete
- **`-ServerOnly`**: Only start the OAuth2 server without running tests
- **`-Verbose`**: Show detailed output from test runs and server startup

### What It Tests
- **C#**: Integration tests marked with `Category=RealIntegration`
- **C++**: Compiled integration test executables (requires build tools)
- **TypeScript**: `real-oauth2-integration.test.ts` file

### Integration Test Coverage
All languages test the following OAuth2 scenarios:
- Server connectivity and health checks
- OAuth2 server discovery
- Client credentials flow (with and without scopes)
- Token introspection (valid and invalid tokens)
- Error handling and network resilience
- Performance and concurrent request handling

### Requirements
- **Docker**: Required for OAuth2 server
- **C#**: .NET SDK
- **TypeScript**: Node.js and npm
- **C++**: Build tools (make, CMake, Visual Studio Build Tools, or GCC)

### OAuth2 Server Details
- **Type**: Node.js-based OAuth2 server
- **Port**: 8081 (mapped from container port 8080)
- **Endpoints**: Standard OAuth2 endpoints (token, introspect, revoke, discovery)
- **Credentials**: 
  - Client ID: `test-client`
  - Client Secret: `test-secret`
- **Health Check**: Automatic readiness verification

### Server Management
The script automatically handles OAuth2 server lifecycle:
1. Starts Docker Compose with OAuth2 server
2. Waits for server to be ready (with health check)
3. Runs integration tests
4. Stops server (unless `-KeepServer` is used)

Manual server management:
```powershell
# Start server manually
docker-compose -f Platform\infra\security\tests\docker-compose.oauth2.yml up -d

# Stop server manually
docker-compose -f Platform\infra\security\tests\docker-compose.oauth2.yml down

# Check server status
docker ps
```

## File Structure

```
Platform/infra/security/tests/
├── docker-compose.oauth2.yml          # OAuth2 server configuration
├── docker/simple-oauth2/              # OAuth2 server implementation
├── dotnet/                            # C# test project
│   ├── Integration/                   # C# integration tests
│   └── CoyoteSense.Security.Client.Tests.csproj
├── cpp/integration/                   # C++ integration tests
│   ├── real_oauth2_integration_test.cpp
│   ├── CMakeLists.txt
│   ├── Makefile
│   └── README.md
└── ts/                               # TypeScript test project
    ├── integration/                  # TypeScript integration tests
    │   └── real-oauth2-integration.test.ts
    ├── unit/                        # TypeScript unit tests
    └── package.json
```

## Troubleshooting

### Common Issues

#### 1. Docker Not Found
```
[ERROR] Docker not found - required for OAuth2 server
```
**Solution**: Install Docker Desktop and ensure it's running.

#### 2. OAuth2 Server Fails to Start
```
[ERROR] OAuth2 server failed to start within timeout
```
**Solutions**:
- Check if port 8081 is already in use
- Verify Docker is running and has sufficient resources
- Check Docker Compose logs: `docker-compose -f Platform\infra\security\tests\docker-compose.oauth2.yml logs`

#### 3. C++ Build Failures
```
[SKIP] No C++ build tools found
```
**Solutions**:
- Install Visual Studio Build Tools (Windows)
- Install MinGW/MSYS2 (Windows)
- Install GCC and make (Linux/macOS)

#### 4. .NET SDK Not Found
```
[SKIP] .NET SDK not found
```
**Solution**: Install .NET SDK 6.0 or later from https://dotnet.microsoft.com/download

#### 5. Node.js/npm Not Found
```
[SKIP] Node.js/npm not found
```
**Solution**: Install Node.js from https://nodejs.org

### Integration Test Failures

If integration tests fail after server startup:
1. Check server accessibility: `curl http://localhost:8081/health`
2. Verify OAuth2 endpoints: `curl http://localhost:8081/.well-known/oauth-authorization-server`
3. Check server logs: `docker logs oauth2-server`

### Performance Considerations

- OAuth2 server typically starts in 10-30 seconds
- Integration tests run in 1-5 seconds per language
- C++ tests require compilation time (10-60 seconds depending on system)

## Best Practices

1. **Development Workflow**: Use `run_tests.ps1` for regular development
2. **Pre-commit**: Run both scripts to ensure full test coverage
3. **CI/CD**: Use `run_tests.ps1` for fast feedback, `run_integration_tests.ps1` for full validation
4. **Debugging**: Use `-KeepServer` and `-Verbose` flags for troubleshooting
5. **Resource Management**: The integration runner automatically cleans up unless `-KeepServer` is used

## Exit Codes

Both scripts use standard exit codes:
- **0**: All tests passed
- **1**: Some tests failed or script encountered errors

This allows for easy integration with build systems and CI/CD pipelines.
