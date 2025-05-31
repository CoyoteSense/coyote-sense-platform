# Authentication Client Design for CoyoteSense KeyVault Integration

## Overview

This document describes the authentication client system design for units to securely interact with the CoyoteSense KeyVault unit. The design leverages the existing HTTP client infrastructure and follows established security patterns in the platform.

## Design Principles

1. **Leverage Existing Infrastructure**: Use the proven HTTP client system with support for multiple modes (Real, Mock, Debug, Simulation)
2. **Consistent Security Patterns**: Follow the established KeyVault authentication flow using Bearer tokens and mTLS
3. **Configuration-Driven**: Support various authentication methods through configuration
4. **Fail-Safe Operations**: Handle authentication failures gracefully with retry logic
5. **Audit & Monitoring**: Provide comprehensive logging and metrics

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Unit Process  │    │ Authentication   │    │  KeyVault Unit  │
│                 │    │     Client       │    │                 │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ Business Logic  │───▶│ AuthService      │───▶│ POST /v1/auth   │
│                 │    │ - Token Mgmt     │    │                 │
│ Secret Access   │◀───│ - HTTP Client    │◀───│ Bearer Token    │
│                 │    │ - Auto Refresh   │    │                 │
│                 │    │ - mTLS Support   │    │ GET /v1/secret  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                         ┌──────▼──────┐
                         │ HTTP Client │
                         │ Infrastructure│
                         │ (Real/Mock/ │
                         │ Debug/Sim)  │
                         └─────────────┘
```

## Component Design

### 1. Authentication Service Interface

```cpp
namespace coyote {
namespace infra {
namespace auth {

class IAuthenticationService {
public:
    virtual ~IAuthenticationService() = default;
    
    // Core authentication operations
    virtual std::future<AuthResult> authenticateAsync(const AuthRequest& request) = 0;
    virtual std::future<bool> validateTokenAsync(const std::string& token) = 0;
    virtual std::future<AuthResult> refreshTokenAsync(const std::string& refreshToken) = 0;
    
    // Token management
    virtual std::string getCurrentToken() const = 0;
    virtual bool isTokenValid() const = 0;
    virtual std::chrono::system_clock::time_point getTokenExpiry() const = 0;
    
    // Connection management
    virtual bool isConnected() const = 0;
    virtual std::future<bool> testConnectionAsync() = 0;
    
    // Metrics and monitoring
    virtual std::shared_ptr<IAuthMetrics> getMetrics() const = 0;
};

}}}
```

### 2. Authentication Request/Response Models

```cpp
namespace coyote {
namespace infra {
namespace auth {

enum class AuthMethod {
    UNIT_ROLE,           // Role-based auth with unit identity
    CLIENT_CERTIFICATE,  // mTLS certificate-based auth
    SERVICE_PRINCIPAL,   // Service principal with client_id/secret
    KUBERNETES_JWT       // Kubernetes service account JWT
};

struct AuthRequest {
    AuthMethod method;
    std::string unitRole;           // For UNIT_ROLE method
    std::string clientId;           // For SERVICE_PRINCIPAL method
    std::string clientSecret;       // For SERVICE_PRINCIPAL method
    std::string jwtToken;           // For KUBERNETES_JWT method
    std::string certificatePath;    // For CLIENT_CERTIFICATE method
    std::string privateKeyPath;     // For CLIENT_CERTIFICATE method
    std::unordered_map<std::string, std::string> additionalClaims;
};

struct AuthResult {
    bool success;
    std::string accessToken;
    std::string refreshToken;
    std::chrono::system_clock::time_point expiresAt;
    std::string errorMessage;
    std::unordered_map<std::string, std::string> metadata;
};

struct AuthConfig {
    std::string keyVaultUrl;        // KeyVault endpoint URL
    AuthMethod authMethod;          // Authentication method to use
    std::string unitRole;           // Unit role for role-based auth
    std::string caCertPath;         // CA certificate for server verification
    std::string clientCertPath;     // Client certificate for mTLS
    std::string clientKeyPath;      // Client private key for mTLS
    bool enableMutualTLS;           // Enable mTLS
    bool verifyServerCert;          // Verify server certificate
    int tokenRefreshBufferSeconds;  // Refresh token X seconds before expiry
    int maxRetryAttempts;           // Max retry attempts for auth failures
    int retryBackoffMs;             // Backoff between retry attempts
    int connectionTimeoutMs;        // Connection timeout
    int requestTimeoutMs;           // Request timeout
};

}}}
```

### 3. KeyVault Authentication Service Implementation

```cpp
namespace coyote {
namespace infra {
namespace auth {

class KeyVaultAuthService : public IAuthenticationService {
private:
    AuthConfig config_;
    std::unique_ptr<IHttpClient> httpClient_;
    std::shared_ptr<IAuthMetrics> metrics_;
    
    // Token management
    mutable std::mutex tokenMutex_;
    std::string currentToken_;
    std::string refreshToken_;
    std::chrono::system_clock::time_point tokenExpiry_;
    
    // Retry logic
    std::unique_ptr<IRetryStrategy> retryStrategy_;
    
public:
    KeyVaultAuthService(const AuthConfig& config, 
                       std::unique_ptr<IHttpClient> httpClient);
    
    // IAuthenticationService implementation
    std::future<AuthResult> authenticateAsync(const AuthRequest& request) override;
    std::future<bool> validateTokenAsync(const std::string& token) override;
    std::future<AuthResult> refreshTokenAsync(const std::string& refreshToken) override;
    
    std::string getCurrentToken() const override;
    bool isTokenValid() const override;
    std::chrono::system_clock::time_point getTokenExpiry() const override;
    
    bool isConnected() const override;
    std::future<bool> testConnectionAsync() override;
    
    std::shared_ptr<IAuthMetrics> getMetrics() const override;

private:
    // Authentication method implementations
    std::future<AuthResult> authenticateWithUnitRole(const AuthRequest& request);
    std::future<AuthResult> authenticateWithCertificate(const AuthRequest& request);
    std::future<AuthResult> authenticateWithServicePrincipal(const AuthRequest& request);
    std::future<AuthResult> authenticateWithKubernetesJWT(const AuthRequest& request);
    
    // Helper methods
    void configureHttpClientSecurity();
    std::string buildAuthUrl() const;
    AuthResult parseAuthResponse(const IHttpResponse& response);
    bool shouldRefreshToken() const;
    void scheduleTokenRefresh();
};

}}}
```

### 4. Authentication Client Factory

```cpp
namespace coyote {
namespace infra {
namespace auth {

class AuthenticationClientFactory {
public:
    static std::unique_ptr<IAuthenticationService> createKeyVaultAuthService(
        const AuthConfig& config,
        std::unique_ptr<IHttpClient> httpClient = nullptr);
    
    static std::unique_ptr<IAuthenticationService> createMockAuthService(
        const AuthConfig& config);
    
    static std::unique_ptr<IAuthenticationService> createFromConfig(
        const std::string& configPath);
    
    static std::unique_ptr<IAuthenticationService> createFromEnvironment();

private:
    static std::unique_ptr<IHttpClient> createDefaultHttpClient(const AuthConfig& config);
    static AuthConfig loadConfigFromFile(const std::string& configPath);
    static AuthConfig loadConfigFromEnvironment();
};

}}}
```

### 5. Integration with SecureStore

The authentication client integrates seamlessly with the existing `SecureStoreFactory`:

```cpp
namespace coyote {
namespace infra {

class SecureStoreFactory : public ISecureStoreFactory {
public:
    std::unique_ptr<ISecureStore> createKeyVault(
        const SecureStoreConfig& config,
        std::unique_ptr<IHttpClient> httpClient) override {
        
        // Create authentication service
        auth::AuthConfig authConfig = convertToAuthConfig(config);
        auto authService = auth::AuthenticationClientFactory::createKeyVaultAuthService(
            authConfig, std::move(httpClient));
        
        // Create authenticated SecureStore
        return std::make_unique<AuthenticatedKeyVaultSecureStore>(
            config, std::move(authService));
    }
};

}}}
```

## Authentication Flow

### 1. Unit Role Authentication (Recommended)

```
1. Unit starts with configured unitRole (e.g., "trading-engine", "payment-processor")
2. AuthService sends POST /v1/auth with {"role": "trading-engine"}
3. KeyVault validates unit identity and returns JWT token
4. Token stored in memory with automatic refresh before expiry
5. All subsequent requests include "Authorization: Bearer <token>"
```

### 2. mTLS Certificate Authentication

```
1. Unit configured with client certificate and private key
2. HTTP client establishes mTLS connection to KeyVault
3. AuthService sends POST /v1/auth with certificate-based identity
4. KeyVault validates client certificate and returns token
5. Subsequent requests use both mTLS and Bearer token
```

### 3. Service Principal Authentication

```
1. Unit configured with client_id and client_secret
2. AuthService sends POST /v1/auth with service principal credentials
3. KeyVault validates credentials and returns token
4. Token refresh handled automatically using refresh token
```

## Configuration Examples

### 1. Role-based Authentication

```json
{
  "authentication": {
    "keyVaultUrl": "https://vault.coyotesense.local:8201",
    "authMethod": "UNIT_ROLE",
    "unitRole": "trading-engine",
    "caCertPath": "/etc/ssl/certs/ca.pem",
    "verifyServerCert": true,
    "tokenRefreshBufferSeconds": 300,
    "maxRetryAttempts": 3,
    "retryBackoffMs": 1000,
    "connectionTimeoutMs": 5000,
    "requestTimeoutMs": 30000
  }
}
```

### 2. mTLS Authentication

```json
{
  "authentication": {
    "keyVaultUrl": "https://vault.coyotesense.local:8201",
    "authMethod": "CLIENT_CERTIFICATE",
    "enableMutualTLS": true,
    "clientCertPath": "/etc/ssl/certs/client.pem",
    "clientKeyPath": "/etc/ssl/private/client.key",
    "caCertPath": "/etc/ssl/certs/ca.pem",
    "verifyServerCert": true,
    "tokenRefreshBufferSeconds": 300
  }
}
```

### 3. Kubernetes JWT Authentication

```json
{
  "authentication": {
    "keyVaultUrl": "https://vault.coyotesense.local:8201",
    "authMethod": "KUBERNETES_JWT",
    "unitRole": "payment-processor",
    "verifyServerCert": true,
    "tokenRefreshBufferSeconds": 300
  }
}
```

## Usage Examples

### C++ Examples

#### 1. Basic Usage

```cpp
#include "coyote/infra/auth/authentication_client_factory.h"
#include "coyote/infra/security/secure_store_factory.h"

// Create authentication service
auto authConfig = auth::AuthenticationClientFactory::loadConfigFromEnvironment();
auto authService = auth::AuthenticationClientFactory::createKeyVaultAuthService(authConfig);

// Create secure store with authentication
auto secureStoreConfig = SecureStoreConfig{
    .key_vault_url = "https://vault.coyotesense.local:8201"
};
auto secureStore = SecureStoreFactory::createKeyVault(secureStoreConfig, authService);

// Use secure store
std::string dbPassword;
if (secureStore->getSecret("database/password", dbPassword)) {
    // Use password securely
    connectToDatabase(dbPassword);
    
    // Clear sensitive data from memory
    std::fill(dbPassword.begin(), dbPassword.end(), '\0');
}
```

#### 2. Advanced Usage with Custom HTTP Client

```cpp
// Create custom HTTP client (e.g., for testing)
auto httpClient = std::make_unique<MockHttpClient>();

// Configure authentication
auth::AuthConfig authConfig{
    .keyVaultUrl = "https://vault.coyotesense.local:8201",
    .authMethod = auth::AuthMethod::UNIT_ROLE,
    .unitRole = "trading-engine",
    .verifyServerCert = true,
    .tokenRefreshBufferSeconds = 300
};

// Create authentication service with custom HTTP client
auto authService = auth::AuthenticationClientFactory::createKeyVaultAuthService(
    authConfig, std::move(httpClient));

// Monitor authentication metrics
auto metrics = authService->getMetrics();
std::cout << "Auth success rate: " << metrics->getSuccessRate() << std::endl;
```

#### 3. Testing with Mock Authentication

```cpp
// For unit testing
auto mockAuthService = auth::AuthenticationClientFactory::createMockAuthService(authConfig);

// Configure mock behavior
auto mockAuth = dynamic_cast<MockAuthenticationService*>(mockAuthService.get());
mockAuth->setAuthResult(auth::AuthResult{
    .success = true,
    .accessToken = "mock-token-123",
    .expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1)
});
```

### C# Examples

#### 1. Basic Usage

```csharp
using Coyote.Infra.Auth;
using Coyote.Infra.Security;

// Create authentication service
var authConfig = AuthenticationClientFactory.LoadConfigFromEnvironment();
var authService = AuthenticationClientFactory.CreateKeyVaultAuthService(authConfig);

// Create secure store with authentication
var secureStoreConfig = new SecureStoreConfig
{
    KeyVaultUrl = "https://vault.coyotesense.local:8201"
};
var secureStore = SecureStoreFactory.CreateKeyVault(secureStoreConfig, authService);

// Use secure store
if (await secureStore.GetSecretAsync("database/password") is { } dbPassword)
{
    // Use password securely
    await ConnectToDatabaseAsync(dbPassword);
    
    // Clear sensitive data from memory
    dbPassword = string.Empty;
}
```

#### 2. Advanced Usage with Configuration

```csharp
// Configure authentication
var authConfig = new AuthConfig
{
    KeyVaultUrl = "https://vault.coyotesense.local:8201",
    AuthMethod = AuthMethod.UnitRole,
    UnitRole = "trading-engine",
    VerifyServerCert = true,
    TokenRefreshBufferSeconds = 300
};

// Create authentication service
var authService = AuthenticationClientFactory.CreateKeyVaultAuthService(authConfig);

// Monitor authentication metrics
var metrics = authService.GetMetrics();
Console.WriteLine($"Auth success rate: {metrics.GetSuccessRate()}");
```

#### 3. Testing with Mock Authentication

```csharp
// For unit testing
var mockAuthService = AuthenticationClientFactory.CreateMockAuthService(authConfig);

// Configure mock behavior
var mockAuth = (MockAuthenticationService)mockAuthService;
mockAuth.SetAuthResult(new AuthResult
{
    Success = true,
    AccessToken = "mock-token-123",
    ExpiresAt = DateTime.UtcNow.AddHours(1)
});
```

### TypeScript Examples

#### 1. Basic Usage

```typescript
import { AuthenticationClientFactory } from '@coyote/infra-auth';
import { SecureStoreFactory } from '@coyote/infra-security';

// Create authentication service
const authConfig = AuthenticationClientFactory.loadConfigFromEnvironment();
const authService = AuthenticationClientFactory.createKeyVaultAuthService(authConfig);

// Create secure store with authentication
const secureStoreConfig = {
    keyVaultUrl: 'https://vault.coyotesense.local:8201'
};
const secureStore = SecureStoreFactory.createKeyVault(secureStoreConfig, authService);

// Use secure store
const dbPassword = await secureStore.getSecret('database/password');
if (dbPassword) {
    // Use password securely
    await connectToDatabase(dbPassword);
    
    // Clear sensitive data from memory
    dbPassword = '';
}
```

#### 2. Advanced Usage with Configuration

```typescript
// Configure authentication
const authConfig: AuthConfig = {
    keyVaultUrl: 'https://vault.coyotesense.local:8201',
    authMethod: AuthMethod.UNIT_ROLE,
    unitRole: 'trading-engine',
    verifyServerCert: true,
    tokenRefreshBufferSeconds: 300
};

// Create authentication service
const authService = AuthenticationClientFactory.createKeyVaultAuthService(authConfig);

// Monitor authentication metrics
const metrics = authService.getMetrics();
console.log(`Auth success rate: ${metrics.getSuccessRate()}`);
```

#### 3. Testing with Mock Authentication

```typescript
// For unit testing
const mockAuthService = AuthenticationClientFactory.createMockAuthService(authConfig);

// Configure mock behavior
const mockAuth = mockAuthService as MockAuthenticationService;
mockAuth.setAuthResult({
    success: true,
    accessToken: 'mock-token-123',
    expiresAt: new Date(Date.now() + 3600000) // 1 hour from now
});
```

### Python Examples

#### 1. Basic Usage

```python
from coyote.infra.auth import AuthenticationClientFactory
from coyote.infra.security import SecureStoreFactory

# Create authentication service
auth_config = AuthenticationClientFactory.load_config_from_environment()
auth_service = AuthenticationClientFactory.create_keyvault_auth_service(auth_config)

# Create secure store with authentication
secure_store_config = {
    'key_vault_url': 'https://vault.coyotesense.local:8201'
}
secure_store = SecureStoreFactory.create_keyvault(secure_store_config, auth_service)

# Use secure store
db_password = await secure_store.get_secret('database/password')
if db_password:
    # Use password securely
    await connect_to_database(db_password)
    
    # Clear sensitive data from memory
    db_password = None
```

#### 2. Advanced Usage with Configuration

```python
from coyote.infra.auth import AuthConfig, AuthMethod

# Configure authentication
auth_config = AuthConfig(
    key_vault_url='https://vault.coyotesense.local:8201',
    auth_method=AuthMethod.UNIT_ROLE,
    unit_role='trading-engine',
    verify_server_cert=True,
    token_refresh_buffer_seconds=300
)

# Create authentication service
auth_service = AuthenticationClientFactory.create_keyvault_auth_service(auth_config)

# Monitor authentication metrics
metrics = auth_service.get_metrics()
print(f"Auth success rate: {metrics.get_success_rate()}")
```

#### 3. Testing with Mock Authentication

```python
from coyote.infra.auth import AuthResult
from datetime import datetime, timedelta

# For unit testing
mock_auth_service = AuthenticationClientFactory.create_mock_auth_service(auth_config)

# Configure mock behavior
mock_auth_service.set_auth_result(AuthResult(
    success=True,
    access_token='mock-token-123',
    expires_at=datetime.utcnow() + timedelta(hours=1)
))
```

## Security Considerations

### 1. Token Security
- Tokens stored only in memory (never persisted to disk)
- Automatic token refresh before expiry
- Immediate token invalidation on process termination
- Secure memory clearing after token use

### 2. Certificate Management
- Client certificates loaded from secure file system locations
- Private keys protected with appropriate file permissions
- CA certificate validation for server identity verification
- Support for certificate rotation without service restart

### 3. Network Security
- All communication over TLS 1.2+
- Optional mTLS for enhanced security
- Certificate pinning support
- Network timeout configuration to prevent hang attacks

### 4. Error Handling
- No sensitive data in error messages or logs
- Secure retry logic with exponential backoff
- Circuit breaker pattern for fault tolerance
- Comprehensive audit logging (without exposing secrets)

## Monitoring and Metrics

### Authentication Metrics Interface

```cpp
class IAuthMetrics {
public:
    virtual ~IAuthMetrics() = default;
    
    // Request metrics
    virtual void incrementAuthAttempts() = 0;
    virtual void incrementAuthSuccesses() = 0;
    virtual void incrementAuthFailures() = 0;
    virtual void recordAuthLatency(std::chrono::milliseconds latency) = 0;
    
    // Token metrics
    virtual void incrementTokenRefreshes() = 0;
    virtual void recordTokenLifetime(std::chrono::seconds lifetime) = 0;
    
    // Connection metrics
    virtual void setConnectionStatus(bool connected) = 0;
    virtual void incrementConnectionFailures() = 0;
    
    // Aggregated metrics
    virtual double getSuccessRate() const = 0;
    virtual double getAverageLatencyMs() const = 0;
    virtual bool isHealthy() const = 0;
    virtual std::chrono::system_clock::time_point getLastSuccessfulAuth() const = 0;
};
```

## Migration Strategy

### Phase 1: Infrastructure Setup
1. Implement core authentication interfaces and base classes
2. Create KeyVaultAuthService with role-based authentication
3. Integrate with existing HTTP client infrastructure
4. Add comprehensive unit tests with mock implementations

### Phase 2: Integration with SecureStore
1. Modify SecureStoreFactory to use authentication service
2. Update existing KeyVaultSecureStore to work with authenticated clients
3. Add configuration loading and validation
4. Create integration tests

### Phase 3: Advanced Features
1. Implement mTLS and certificate-based authentication
2. Add Kubernetes JWT authentication support
3. Implement retry strategies and circuit breaker patterns
4. Add comprehensive monitoring and metrics

### Phase 4: Production Deployment
1. Update unit configurations to use authentication service
2. Deploy KeyVault unit with authentication endpoints
3. Configure certificates and security policies
4. Monitor and tune performance

## Backward Compatibility

The design maintains backward compatibility with existing SecureStore implementations:

1. **Existing SecureStore Interface**: No changes to ISecureStore interface
2. **Configuration**: New authentication configuration is additive
3. **Factory Pattern**: SecureStoreFactory enhanced but existing methods preserved
4. **HTTP Client**: Leverages existing HTTP client infrastructure without changes

## Implementation Priority

### High Priority (MVP)
1. Core authentication interfaces (IAuthenticationService, AuthConfig, etc.)
2. KeyVaultAuthService with role-based authentication
3. Integration with existing HTTP client infrastructure
4. Basic error handling and retry logic

### Medium Priority
1. mTLS certificate-based authentication
2. Service principal authentication
3. Comprehensive metrics and monitoring
4. Configuration file loading

### Low Priority (Future Enhancements)
1. Kubernetes JWT authentication
2. Advanced retry strategies (circuit breaker, bulkhead)
3. Certificate rotation support
4. Performance optimizations

## Conclusion

This authentication client design provides a robust, secure, and extensible foundation for units to interact with the CoyoteSense KeyVault. By leveraging the existing HTTP client infrastructure and following established security patterns, the solution integrates seamlessly with the current architecture while providing the flexibility needed for various deployment scenarios and authentication methods.

The design prioritizes security best practices, operational simplicity, and maintainability while ensuring backward compatibility with existing components.
