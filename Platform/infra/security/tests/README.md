# OAuth2 Authentication Client Tests

This directory contains comprehensive tests for all OAuth2 authentication client libraries in the CoyoteSense platform.

## Test Structure

```
tests/
├── cpp/                    # C++ OAuth2 client tests
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── mocks/             # Mock implementations
├── csharp/                # C# OAuth2 client tests
│   ├── Unit/              # Unit tests
│   ├── Integration/       # Integration tests
│   └── Mocks/             # Mock implementations
├── python/                # Python OAuth2 client tests
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── mocks/             # Mock implementations
├── typescript/            # TypeScript/JavaScript OAuth2 client tests
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── mocks/             # Mock implementations
├── common/                # Shared test utilities and mock servers
│   ├── mock-oauth2-server/ # Mock OAuth2 server for testing
│   └── test-data/         # Common test data and certificates
└── scripts/               # Test runner scripts
    ├── run-all-tests.ps1  # Run all tests across all languages
    ├── run-unit-tests.ps1 # Run only unit tests
    └── run-integration-tests.ps1 # Run only integration tests
```

## Test Coverage

Each OAuth2 client implementation includes tests for:

### Unit Tests
- **Configuration validation** - Test config parsing and validation
- **OAuth2 flows** - Test each grant type individually
- **Token management** - Test token storage, refresh, and expiration
- **Error handling** - Test various error conditions
- **Logging** - Test logging functionality
- **Factory patterns** - Test client creation and configuration

### Integration Tests
- **Real OAuth2 server** - Test against actual OAuth2 server
- **End-to-end flows** - Complete authentication workflows
- **mTLS authentication** - Test certificate-based authentication
- **Token introspection** - Test token validation endpoints
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
