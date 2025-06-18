# .NET Security Component - Mode-Based Authentication Client

## Overview

The .NET Security component provides a clean, modular authentication client that supports multiple runtime modes (Production, Testing, Debug) with a modern factory-based architecture.

## Architecture

### Directory Structure
```
src/dotnet/
├── interfaces/          # Interface definitions and base classes
│   ├── IAuthClient.cs           # Main authentication interface
│   ├── AuthInterfaces.cs        # Supporting interfaces (AuthResult, AuthToken, etc.)
│   └── BaseAuthClient.cs        # Abstract base class with common functionality
├── factory/             # Factory implementation for mode-based client creation
│   └── AuthClientFactory.cs     # Factory interface and implementation
├── config/              # Configuration classes
│   ├── AuthClientOptions.cs     # Main authentication configuration
│   ├── AuthClientModeOptions.cs # Mode-specific configuration
│   └── SecureStoreOptions.cs    # Secure storage configuration
├── impl/                # Mode-specific implementations
│   ├── real/           # Production implementation
│   │   └── AuthClientReal.cs
│   ├── mock/           # Testing implementation
│   │   └── AuthClientMock.cs
│   └── debug/          # Debug implementation with enhanced logging
│       └── AuthClientDebug.cs
└── security/           # Security utilities
    └── SecureCredentialProvider.cs
```

### Key Design Principles

1. **Mode-Based Architecture**: Supports different runtime modes for various environments
2. **Interface-Driven**: Clean separation between interface and implementation
3. **Factory Pattern**: Centralized creation logic with dependency injection support
4. **Configuration-First**: Driven by appsettings.json and environment variables
5. **No Legacy Baggage**: Clean, modern implementation without backward compatibility constraints

### Supported Runtime Modes

- **Production**: Uses real authentication servers with full OAuth2/JWT support
- **Testing**: Uses mock implementations for unit/integration testing
- **Debug**: Wraps production implementation with detailed logging
- **Recording/Replay/Simulation**: Mapped to appropriate implementations

## Usage

### 1. Dependency Injection Setup

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Coyote.Infra.Security.Auth;

// Register with configuration file
services.AddCoyoteAuthClient(Configuration);

// Or register with explicit configuration
services.AddCoyoteAuthClient(
    configureAuth: options =>
    {
        options.ClientId = "your-client-id";
        options.ClientSecret = "your-client-secret";
        options.TokenUrl = "https://auth.example.com/token";
        options.AuthorizationUrl = "https://auth.example.com/authorize";
        options.BaseUrl = "https://auth.example.com";
    },
    configureMode: options =>
    {
        options.Mode = RuntimeMode.Production;
        options.Debug.LogRequests = true;
        options.Mock.SimulateFailures = false;
    }
);
```

### 2. Configuration File (appsettings.json)

```json
{
  "Coyote": {
    "Auth": {
      "ClientId": "your-client-id",
      "ClientSecret": "your-client-secret", 
      "TokenUrl": "https://auth.example.com/token",
      "AuthorizationUrl": "https://auth.example.com/authorize",
      "BaseUrl": "https://auth.example.com",
      "EnableDebugLogging": true,
      "Mode": {
        "Mode": "Production",
        "Mock": {
          "DefaultExpirationSeconds": 3600,
          "SimulateFailures": false,
          "ResponseDelayMs": 100,
          "LogOperations": true
        },
        "Debug": {
          "LogRequests": true,
          "LogResponses": true,
          "LogTokens": false,
          "LogHeaders": true,
          "LogBodies": false
        },
        "Real": {
          "ConnectionTimeoutMs": 30000,
          "RequestTimeoutMs": 60000,
          "MaxRetryAttempts": 3,
          "RetryDelayMs": 1000,
          "EnableTokenCaching": true,
          "TokenBufferSeconds": 300
        }
      }
    }
  }
}
```

### 3. Basic Usage

```csharp
using Coyote.Infra.Security.Auth;

public class MyService
{
    private readonly IAuthClient _authClient;
    
    public MyService(IAuthClient authClient)
    {
        _authClient = authClient;
    }
    
    public async Task<string> GetAccessTokenAsync()
    {
        // The factory automatically provides the correct implementation
        // based on the current runtime mode
        var result = await _authClient.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess && result.Token != null)
        {
            return result.Token.AccessToken;
        }
        
        throw new InvalidOperationException($"Authentication failed: {result.ErrorMessage}");
    }
    
    public async Task<bool> TestConnectionAsync()
    {
        return await _authClient.TestConnectionAsync();
    }
}
```

### 4. Factory Usage (Advanced)

```csharp
using Coyote.Infra.Security.Auth;

public class MyService
{
    private readonly IAuthClientFactory _factory;
    
    public MyService(IAuthClientFactory factory)
    {
        _factory = factory;
    }
    
    public async Task TestDifferentModes()
    {
        // Create client for current mode
        using var currentClient = _factory.CreateClient();
        
        // Create client for specific mode
        using var testClient = _factory.CreateAuthClientForMode(RuntimeMode.Testing);
        using var debugClient = _factory.CreateAuthClientForMode(RuntimeMode.Debug);
        
        // Use the clients...
        var result1 = await currentClient.AuthenticateClientCredentialsAsync();
        var result2 = await testClient.AuthenticateClientCredentialsAsync();
        var result3 = await debugClient.AuthenticateClientCredentialsAsync();
    }
}
```

### 5. Environment Variables

Override the runtime mode using environment variables:

```bash
# Set runtime mode via environment variable
export COYOTE_RUNTIME_MODE=Debug
# or
export MODE=Testing
```

## Implementation Details

### BaseAuthClient

Provides common functionality for all authentication implementations:
- Thread-safe token storage and validation
- Debug logging utilities
- Proper dispose pattern
- Token expiration checking
- Common helper methods

### Mode-Specific Implementations

- **RealAuthClient**: Full OAuth2/JWT authentication using HttpClient with retry logic, timeout handling, and proper error management
- **MockAuthClient**: Generates realistic fake tokens for testing with configurable delays and failure simulation
- **DebugAuthClient**: Wraps RealAuthClient with comprehensive logging for debugging and troubleshooting

### Factory Pattern

The `IAuthClientFactory` interface provides:
- Automatic mode detection from configuration and environment variables
- Type-safe dependency injection integration
- Centralized client creation logic
- Easy testing and mocking

## Authentication Standards Supported

- **OAuth2 Client Credentials** (RFC 6749)
- **OAuth2 Authorization Code** (RFC 6749)
- **OAuth2 Authorization Code + PKCE** (RFC 7636)
- **JWT Bearer Token** (RFC 7523)
- **Token introspection and revocation**
- **Server discovery and metadata**

## Benefits

1. **Simplicity**: Clean, straightforward API without legacy complexity
2. **Testability**: Easy switching between real and mock implementations
3. **Debuggability**: Comprehensive logging in debug mode
4. **Consistency**: Follows platform-wide architectural patterns
5. **Configurability**: Runtime behavior controlled by configuration
6. **Standards Compliance**: Implements OAuth2 and JWT standards correctly
7. **Production Ready**: Includes retry logic, timeouts, and error handling

## Migration Notes

This is a completely new implementation designed for greenfield projects. There are no legacy compatibility concerns or migration paths needed.
