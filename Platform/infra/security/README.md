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
```bash
cd src/python
pip install -e .
```

```python
from coyote_infra_security import AuthClientConfig, AuthMode, create_auth_client

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
result = await auth_client.authenticate_client_credentials_async()
if result.success:
    token = result.token
    print(f"Access token: {token.access_token}")
```

### TypeScript
```bash
cd src/ts
npm install
```

```typescript
import { OAuth2AuthClientFactory } from '@coyotesense/oauth2-client-ts';

const client = OAuth2AuthClientFactory.createClientCredentials(
  'https://auth.coyotesense.io',
  'my-client-id',
  'my-client-secret',
  ['read', 'write']
);

const result = await client.clientCredentialsAsync();
if (result.success && result.token) {
  console.log('Access Token:', result.token.accessToken);
}
```

### C#
```bash
cd src/dotnet
dotnet build
```

```csharp
using Coyote.Infra.Security.Auth;

var config = new AuthClientConfig
{
    ServerUrl = "https://auth.yourbroker.com",
    ClientId = "your-client-id",
    ClientSecret = "your-client-secret",
    AuthMode = AuthMode.ClientCredentials
};

var authClient = AuthClientFactory.CreateClient(config, "real");
var result = await authClient.AuthenticateClientCredentialsAsync();
```

### C++
```bash
cd src/cpp
mkdir build && cd build
cmake ..
make
```

```cpp
#include <coyote_infra_security/auth_client.hpp>

auto config = AuthClientConfig{
    .server_url = "https://auth.yourbroker.com",
    .client_id = "your-client-id",
    .client_secret = "your-client-secret",
    .auth_mode = AuthMode::ClientCredentials
};

auto auth_client = create_auth_client(config, "real");
auto result = auth_client->authenticate_client_credentials();
```

## Testing

### Run All Tests
```bash
cd tests
./run_tests.ps1          # Unit tests (mock-based)
./run_integration_tests.ps1  # Integration tests (real OAuth2 server)
```

### OAuth2 Server Management
```bash
./manage-oauth2-server.ps1 start   # Start test OAuth2 server
./manage-oauth2-server.ps1 stop    # Stop test OAuth2 server
```

## Documentation

- **Main Tests Guide**: [tests/README.md](tests/README.md)
- **OAuth2 Setup**: [tests/OAUTH2_INTEGRATION_SETUP.md](tests/OAUTH2_INTEGRATION_SETUP.md)
- **C# Implementation**: [src/dotnet/README.md](src/dotnet/README.md)
- **TypeScript Implementation**: [src/ts/README.md](src/ts/README.md)

## Security Considerations

1. **Token Storage**: Store tokens securely using appropriate storage mechanisms
2. **HTTPS Only**: Always use HTTPS for OAuth2 endpoints
3. **PKCE**: Always use PKCE for Authorization Code flow
4. **Client Secrets**: Keep client secrets secure and never expose in client-side code
5. **Token Expiration**: Respect token expiration times and refresh appropriately
6. **Scope Limitation**: Request only necessary scopes
7. **State Parameter**: Always use state parameter to prevent CSRF attacks

## Support

For support and questions:
- GitHub Issues: [Create an issue](https://github.com/coyotesense/coyote-sense-platform/issues)
- Documentation: [CoyoteSense Docs](https://docs.coyotesense.io)
