# Security Infrastructure Component

## Overview
The Security component provides comprehensive authentication and security functionality for the CoyoteSense platform. It supports multiple authentication standards including OAuth2, JWT Bearer, and mTLS for secure communication with trading APIs, data feeds, and other services.

## Features

### Authentication Standards Support
- **OAuth2 Client Credentials** (RFC 6749) - For service-to-service authentication
- **OAuth2 Authorization Code** (RFC 6749) - For user authentication flows  
- **OAuth2 + PKCE** (RFC 7636) - Enhanced security for public clients
- **JWT Bearer** (RFC 7523) - For JWT-based authentication
- **mTLS Client Credentials** (RFC 8705) - Mutual TLS authentication

### Key Capabilities
- **Multi-language Support**: Python, TypeScript, C++, .NET implementations
- **Runtime Modes**: Real, Mock, Debug, Record, Replay, Simulation
- **Automatic Token Management**: Auto-refresh, expiry handling, secure storage
- **Comprehensive Logging**: Debug tracing, performance monitoring
- **Error Handling**: Retry logic, connection testing, graceful failures
- **Extensible Design**: Plugin architecture for custom authentication flows

## Architecture

### Component Structure
```
Platform/infra/security/
├── src/                    # Implementation source code
│   ├── python/             # Python implementation
│   │   ├── interfaces/     # Python interfaces and types
│   │   │   ├── auth_client.py   # Core authentication interfaces
│   │   │   └── __init__.py      # Interface exports
│   │   ├── factory/        # Client factory functions
│   │   │   ├── auth_client_factory.py  # Factory implementation
│   │   │   └── __init__.py              # Factory exports
│   │   ├── impl/           # Runtime mode implementations
│   │   │   ├── real/       # Production implementation
│   │   │   │   ├── auth_client_real.py
│   │   │   │   └── __init__.py
│   │   │   ├── mock/       # Testing implementation
│   │   │   │   ├── auth_client_mock.py
│   │   │   │   └── __init__.py
│   │   │   ├── debug/      # Debug implementation
│   │   │   │   ├── auth_client_debug.py
│   │   │   │   └── __init__.py
│   │   │   └── __init__.py
│   │   ├── pyproject.toml  # Python package configuration
│   │   └── __init__.py     # Main Python package
│   ├── ts/                 # TypeScript implementation
│   ├── cpp/                # C++ implementation
│   └── dotnet/             # .NET implementation
├── examples/               # Usage examples and tutorials
├── tests/                  # Component tests
├── modes/                  # Runtime mode configurations
└── README.md              # This file
```

## Supported Languages
- **Python** (asyncio-based, pip installable)
- **TypeScript** (Promise-based, npm installable)  
- **C++** (CMake build, vcpkg dependencies)
- **C#/.NET** (dotnet build, NuGet packages)

## Runtime Modes
- **Real**: Production implementation with actual authentication servers
- **Mock**: Testing implementation with simulated authentication behavior
- **Debug**: Enhanced logging and debugging capabilities
- **Record**: Record authentication flows for replay
- **Replay**: Replay recorded authentication flows
- **Simulation**: Simulated authentication for testing scenarios

## Quick Start

### Python

#### Installation
```bash
cd src/python
pip install -e .
```

#### Basic Usage
```python
from coyote_infra_security import (
    AuthClientConfig, AuthMode, create_auth_client
)

# Configure authentication
config = AuthClientConfig(
    server_url="https://auth.yourbroker.com",
    client_id="your-trading-client-id",
    client_secret="your-client-secret",
    auth_mode=AuthMode.CLIENT_CREDENTIALS,
    default_scopes=["trading", "market-data"]
)

# Create client
auth_client = create_auth_client(config, mode="real")

# Authenticate
result = auth_client.authenticate_client_credentials()
if result.success:
    token = result.token
    print(f"Access token: {token.access_token}")
    
    # Use token in API calls
    headers = {"Authorization": token.get_authorization_header()}
```

#### Async Usage
```python
import asyncio

async def trading_auth_example():
    # Create client
    auth_client = create_auth_client(config, mode="real")
    
    # Authenticate asynchronously
    result = await auth_client.authenticate_client_credentials_async(
        scopes=["trading", "portfolio"]
    )
    
    if result.success:
        # Get valid token (auto-refreshes if needed)
        token = await auth_client.get_valid_token_async()
        return token
    
    return None

# Run async
token = asyncio.run(trading_auth_example())
```

### Mock Mode for Testing
```python
# Create mock client for testing
mock_client = create_auth_client(config, mode="mock")

# Configure mock behavior
mock_client.set_response_delay(100)  # 100ms delay
mock_client.set_failure_rate(0.1)    # 10% failure rate

# Test authentication
result = mock_client.authenticate_client_credentials()
assert result.success
```

### Debug Mode
```python
# Create debug client with enhanced logging
debug_client = create_auth_client(
    config, 
    mode="debug",
    custom_config={
        "trace_requests": True,
        "trace_responses": True,
        "performance_tracking": True
    }
)

# Authenticate with detailed logs
result = debug_client.authenticate_client_credentials()

# Get performance statistics
stats = debug_client.get_performance_stats()
print(f"Auth time: {stats['authenticate_client_credentials']['last_duration_seconds']:.3f}s")
```

## Advanced Usage

### JWT Bearer Authentication
```python
config = AuthClientConfig(
    server_url="https://auth.yourbroker.com",
    client_id="algo-trading-service",
    auth_mode=AuthMode.JWT_BEARER,
    jwt_signing_key_path="/path/to/private-key.pem",
    jwt_issuer="your-platform",
    jwt_audience="https://api.yourbroker.com"
)

auth_client = create_auth_client(config, mode="real")
result = await auth_client.authenticate_jwt_bearer_async(
    subject="trader-001",
    scopes=["trading", "analytics"]
)
```

### Authorization Code with PKCE
```python
config = AuthClientConfig(
    server_url="https://auth.yourbroker.com",
    client_id="trader-dashboard",
    auth_mode=AuthMode.AUTHORIZATION_CODE_PKCE,
    redirect_uri="http://localhost:8080/callback"
)

auth_client = create_auth_client(config, mode="real")

# Step 1: Start authorization flow
auth_url, code_verifier, state = await auth_client.start_authorization_code_flow_async(
    redirect_uri="http://localhost:8080/callback",
    scopes=["profile", "trading"]
)

# Step 2: Redirect user to auth_url
# Step 3: Handle callback and extract authorization code
# Step 4: Exchange code for tokens
result = await auth_client.authenticate_authorization_code_async(
    authorization_code=auth_code_from_callback,
    redirect_uri="http://localhost:8080/callback",
    code_verifier=code_verifier
)
```

### Custom Token Storage
```python
from coyote_infra_security import IAuthTokenStorage

class RedisTokenStorage(IAuthTokenStorage):
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def store_token_async(self, client_id: str, token: AuthToken) -> None:
        # Store token in Redis
        await self.redis.set(f"auth_token:{client_id}", token.access_token)
    
    def get_token(self, client_id: str) -> Optional[AuthToken]:
        # Retrieve token from Redis
        token_data = self.redis.get(f"auth_token:{client_id}")
        if token_data:
            return AuthToken(access_token=token_data)
        return None

# Use custom storage
custom_storage = RedisTokenStorage(redis_client)
auth_client = create_auth_client(
    config, 
    mode="real",
    token_storage=custom_storage
)
```

## Building

### All Languages
```powershell
# From component root
.\build.ps1
```

### Language-Specific Builds

#### Python
```bash
cd src/python
pip install -e .
python -m pytest ../../tests/python/
```

#### TypeScript
```bash
cd src/ts
npm install
npm run build
npm test
```

#### C++
```bash
cd src/cpp
cmake -B build -S .
cmake --build build --config Release
./build/tests/coyote_infra_security_tests
```

#### .NET
```bash
cd src/dotnet
dotnet restore
dotnet build --configuration Release
dotnet test
```

## Configuration

### Environment Variables
```bash
# Authentication server settings
COYOTE_AUTH_SERVER_URL=https://auth.yourbroker.com
COYOTE_AUTH_CLIENT_ID=your-client-id
COYOTE_AUTH_CLIENT_SECRET=your-client-secret

# TLS/SSL settings
COYOTE_AUTH_CLIENT_CERT_PATH=/path/to/client.crt
COYOTE_AUTH_CLIENT_KEY_PATH=/path/to/client.key
COYOTE_AUTH_CA_CERT_PATH=/path/to/ca.crt

# JWT settings
COYOTE_AUTH_JWT_KEY_PATH=/path/to/jwt-signing-key.pem
COYOTE_AUTH_JWT_ISSUER=your-platform
COYOTE_AUTH_JWT_AUDIENCE=https://api.yourbroker.com
```

### Configuration Files
```yaml
# config/auth.yaml
authentication:
  server_url: "https://auth.yourbroker.com"
  client_id: "trading-client-001"
  auth_mode: "client_credentials"
  default_scopes: ["trading", "market-data", "analytics"]
  auto_refresh: true
  refresh_buffer_seconds: 300
  timeout_ms: 30000
  verify_ssl: true
```

## Testing

### Run Tests
```bash
# Python tests
cd tests/python
python -m pytest test_auth_basic.py -v

# Run with coverage
python -m pytest --cov=coyote_infra_security --cov-report=html

# TypeScript tests
cd tests/ts
npm test

# C++ tests
cd tests/cpp
./build/tests/security_tests --gtest_output=xml:test_results.xml

# .NET tests
cd tests/dotnet
dotnet test --logger trx --results-directory ./TestResults
```

### Integration Tests
```bash
# Run integration tests against real auth server
cd tests/integration
python test_real_auth_integration.py --auth-server https://auth.example.com
```

## Examples

The `examples/` directory contains comprehensive examples:

- **`python/auth_examples.py`**: Complete authentication flow examples
- **`python/trading_bot_example.py`**: Trading bot authentication
- **`ts/auth_examples.ts`**: TypeScript authentication examples
- **`cpp/auth_examples.cpp`**: C++ authentication examples
- **`dotnet/AuthExamples.cs`**: .NET authentication examples

## Performance

### Benchmarks
The Security component is optimized for trading environments:

- **Authentication latency**: < 100ms (typical)
- **Token refresh**: < 50ms (cached)
- **Memory usage**: < 10MB per client
- **Concurrent clients**: Supports 1000+ concurrent authentications

### Performance Monitoring
```python
# Enable performance tracking
debug_client = create_auth_client(config, mode="debug")
result = debug_client.authenticate_client_credentials()

# Get performance stats
stats = debug_client.get_performance_stats()
print(f"Auth calls: {stats['authenticate_client_credentials']['call_count']}")
print(f"Avg duration: {stats['authenticate_client_credentials']['average_duration_seconds']:.3f}s")
```

## Security Considerations

### Token Security
- Tokens are never logged in production mode
- Automatic token rotation and refresh
- Secure token storage with optional encryption
- Token revocation on application shutdown

### TLS/SSL
- mTLS support for enhanced security
- Certificate validation and rotation
- Configurable SSL/TLS settings
- Support for custom CA certificates

### Best Practices
1. Use `debug` mode only in development
2. Store secrets in secure key management systems
3. Rotate client secrets regularly
4. Monitor authentication failures and rate limits
5. Use appropriate scopes for least privilege access

## Troubleshooting

### Common Issues

#### Authentication Failures
```bash
# Check configuration
python -c "from coyote_infra_security import AuthClientConfig; print(config.is_valid())"

# Test connection
python -c "auth_client.test_connection()"

# Enable debug logging
export COYOTE_LOG_LEVEL=DEBUG
```

#### Token Refresh Issues
```python
# Check token expiry
token = auth_client.current_token
if token:
    print(f"Token expires at: {token.expires_at}")
    print(f"Needs refresh: {token.needs_refresh()}")
```

#### SSL/TLS Issues
```bash
# Verify certificates
openssl verify -CAfile ca.crt client.crt

# Test SSL connection
openssl s_client -connect auth.yourbroker.com:443 -cert client.crt -key client.key
```

### Debug Mode
```python
# Create debug client for troubleshooting
debug_client = create_auth_client(
    config, 
    mode="debug",
    custom_config={
        "trace_requests": True,
        "trace_responses": True,
        "log_tokens": True  # Only for debugging!
    }
)

# Export debug information
debug_info = debug_client.export_debug_info()
with open("auth_debug.json", "w") as f:
    json.dump(debug_info, f, indent=2)
```

## Contributing

### Development Setup
```bash
# Clone repository
git clone https://github.com/coyotesense/coyote-sense-platform.git
cd coyote-sense-platform/Platform/infra/security

# Install development dependencies
cd src/python
pip install -e ".[dev,test]"

# Run tests
python -m pytest tests/ -v

# Run linting
black src/python/
isort src/python/
mypy src/python/
```

### Adding New Authentication Methods
1. Update interface definitions in `interfaces/<language>/`
2. Implement in `src/<language>/impl/real/`
3. Add mock implementation in `src/<language>/impl/mock/`
4. Update factory in `src/<language>/factory/`
5. Add tests in `tests/<language>/`
6. Update examples and documentation

## License

This component is part of the CoyoteSense Platform and is subject to the platform's licensing terms.

## Support

For issues and questions:
- **Documentation**: https://docs.coyotesense.io/security
- **GitHub Issues**: https://github.com/coyotesense/coyote-sense-platform/issues
- **Community**: https://community.coyotesense.io

#### TypeScript
```bash
cd src/ts
npm install
npm run build
npm start
```

## Testing

### All Tests
```powershell
.\test.ps1
```

### Language-Specific Tests
```bash
# .NET
cd src/dotnet && dotnet test

# C++
cd src/cpp && ctest --test-dir build

# Python  
cd src/python && pytest

# TypeScript
cd src/ts && npm test
```

## Configuration

Runtime mode is controlled via the MODE environment variable:
```bash
export MODE=real    # or mock, debug
```

Mode-specific configurations are stored in:
- modes/real/ - Production configuration
- modes/mock/ - Testing configuration  
- modes/debug/ - Debug configuration

## Docker Support

Build Docker images for each language:
```bash
# Build all language images
docker-compose -f modes/real/docker-compose.yml build

# Build specific language
docker build -f src/dotnet/Dockerfile -t coyote/infra-security-dotnet .
```

## API Reference

[Link to detailed API documentation]

## Examples

See the modes/ directory for configuration examples and the language-specific src/ directories for implementation examples.

## Contributing

1. Follow the established patterns in other infrastructure components
2. Ensure all tests pass across all supported languages
3. Update this README with any new features or changes
4. Test in all three runtime modes (real, mock, debug)
