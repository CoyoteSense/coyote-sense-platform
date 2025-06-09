# OAuth2 AuthClient Interface Design

## Overview

The OAuth2 AuthClient implementation follows a sophisticated design pattern that separates configuration-time concerns from runtime execution concerns. This document explains the interface design, factory pattern, parameter splitting logic, and the architectural purposes behind these decisions.

## Architecture Components

### 1. Interface Layer (`IAuthClient`)

The `IAuthClient` interface defines the runtime contract for OAuth2 authentication operations:

```csharp
public interface IAuthClient : IDisposable
{
    // Core authentication flows
    Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default);
    Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default);
    Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default);
    
    // Authorization Code flow helpers
    (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null);
    
    // Token management
    Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);
    Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default);
    
    // Token operations
    Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default);
    Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default);
    
    // Server operations
    Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default);
    Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default);
    
    // State management
    void ClearTokens();
    AuthToken? CurrentToken { get; }
    bool IsAuthenticated { get; }
}
```

**Purpose**: Defines what operations can be performed at runtime with dynamic parameters.

### 2. Factory Layer (`AuthClientFactory`)

The factory provides a fluent API for configuring client capabilities and static settings:

```csharp
public class AuthClientFactory
{
    public static AuthClientBuilder CreateBuilder(string serverUrl, string clientId);
}

public class AuthClientBuilder
{
    // Flow configuration
    public AuthClientBuilder WithClientCredentialsFlow(string clientSecret);
    public AuthClientBuilder WithJwtBearerFlow(string privateKeyPath, string keyId);
    public AuthClientBuilder WithAuthorizationCodeFlow(string clientSecret);
    
    // Default settings
    public AuthClientBuilder WithDefaultScopes(params string[] scopes);
    public AuthClientBuilder WithDefaultRedirectUri(string redirectUri);
    
    // Security settings
    public AuthClientBuilder WithTlsConfiguration(string certPath, string keyPath);
    public AuthClientBuilder WithTimeout(int timeoutMs);
    
    // Build final client
    public IAuthClient Build();
}
```

**Purpose**: Configures what the client is capable of doing and sets up default behaviors.

## Parameter Splitting Logic

### Configuration vs Runtime Parameters

The design intentionally splits parameters between configuration time (factory) and runtime (interface):

| **Parameter Type** | **Factory (Configuration)** | **Interface (Runtime)** | **Rationale** |
|-------------------|---------------------------|------------------------|---------------|
| **Static Credentials** | `clientSecret`, `privateKeyPath` | - | Security: Configure once, never expose at runtime |
| **Capability Flags** | `WithClientCredentialsFlow()` | - | Architecture: Define what flows are available |
| **Default Values** | `WithDefaultScopes()` | `scopes` parameter | Flexibility: Defaults with per-call overrides |
| **Runtime Data** | - | `authorizationCode`, `codeVerifier` | Logic: Only available during execution |
| **Call-Specific** | - | `redirectUri`, `token` | Context: Varies per operation |

### Example: Authorization Code Flow

#### Factory Configuration (Static Setup)
```csharp
var client = AuthClientFactory.CreateBuilder("https://auth.server.com", "my-client-id")
    .WithAuthorizationCodeFlow(clientSecret: "static-secret")  // ✅ Configure capability
    .WithDefaultScopes("profile", "email")                      // ✅ Set defaults
    .WithDefaultRedirectUri("https://myapp.com/callback")       // ✅ Common redirect
    .Build();
```

#### Interface Usage (Dynamic Execution)
```csharp
// Step 1: Start flow with runtime parameters
var (authUrl, verifier, state) = client.StartAuthorizationCodeFlow(
    redirectUri: "https://myapp.com/special-callback",  // ✅ Override default
    scopes: ["profile", "email", "calendar"],           // ✅ Override defaults
    state: "custom-state-123"                           // ✅ Runtime-specific
);

// Step 2: Complete flow with received data
var result = await client.AuthenticateAuthorizationCodeAsync(
    authorizationCode: "code-from-oauth-server",        // ✅ Runtime-only data
    redirectUri: "https://myapp.com/special-callback",  // ✅ Must match step 1
    codeVerifier: verifier                              // ✅ From step 1
);
```

## Design Purposes

### 1. **Security Isolation**

**Problem**: Sensitive credentials shouldn't be passed around at runtime.

**Solution**: Configure secrets once in the factory, never expose them in method calls.

```csharp
// ❌ BAD: Secrets in every call
await client.AuthenticateAsync("client-secret", "authorization-code");

// ✅ GOOD: Secrets configured once
var client = factory.WithAuthorizationCodeFlow("client-secret").Build();
await client.AuthenticateAuthorizationCodeAsync("authorization-code", redirectUri);
```

### 2. **Separation of Concerns**

**Problem**: Mixing configuration logic with execution logic creates complexity.

**Solution**: Factory handles "what can this client do", interface handles "what should this call do".

```csharp
// Factory: Architectural decisions
var client = factory
    .WithClientCredentialsFlow(secret)    // ✅ This client supports client credentials
    .WithJwtBearerFlow(privateKey)        // ✅ This client supports JWT bearer
    .Build();

// Interface: Execution decisions  
await client.AuthenticateClientCredentialsAsync();  // ✅ Use client credentials now
await client.AuthenticateJwtBearerAsync();          // ✅ Use JWT bearer now
```

### 3. **Flexibility and Reusability**

**Problem**: Clients configured for one specific scenario aren't reusable.

**Solution**: Configure capabilities broadly, specify behavior narrowly.

```csharp
// One client, multiple scenarios
var client = factory
    .WithAuthorizationCodeFlow(secret)
    .WithDefaultScopes("basic")
    .Build();

// Different calls, different parameters
await client.AuthenticateAuthorizationCodeAsync(code1, "https://app1.com/callback");
await client.AuthenticateAuthorizationCodeAsync(code2, "https://app2.com/callback");

// Override defaults per call
var (url1, _, _) = client.StartAuthorizationCodeFlow("https://app1.com/callback", ["basic"]);
var (url2, _, _) = client.StartAuthorizationCodeFlow("https://app2.com/callback", ["basic", "premium"]);
```

### 4. **Type Safety and Validation**

**Problem**: Invalid configurations should be caught at build time, not runtime.

**Solution**: Factory validates configuration, interface validates runtime parameters.

```csharp
// ❌ Caught at build time
var client = factory
    .WithAuthorizationCodeFlow("")  // ✅ Factory validates: throws immediately
    .Build();

// ❌ Caught at call time  
await client.AuthenticateAuthorizationCodeAsync(
    authorizationCode: "",          // ✅ Interface validates: clear error
    redirectUri: "invalid-uri"      // ✅ Interface validates: clear error
);
```

## Implementation Patterns

### 1. **Builder Pattern (Factory)**

```csharp
public class AuthClientBuilder
{
    private readonly AuthClientConfig _config = new();
    
    public AuthClientBuilder WithClientCredentialsFlow(string clientSecret)
    {
        _config.SupportedFlows.Add(AuthFlow.ClientCredentials);
        _config.ClientSecret = clientSecret;
        return this;  // ✅ Fluent chaining
    }
    
    public IAuthClient Build()
    {
        ValidateConfiguration();  // ✅ Validate before building
        return new AuthClient(_config);
    }
}
```

### 2. **Command Pattern (Interface)**

```csharp
public async Task<AuthResult> AuthenticateAuthorizationCodeAsync(
    string authorizationCode, 
    string redirectUri, 
    string? codeVerifier = null, 
    CancellationToken cancellationToken = default)
{
    // ✅ Validate runtime parameters
    ValidateAuthorizationCode(authorizationCode);
    ValidateRedirectUri(redirectUri);
    
    // ✅ Use pre-configured settings + runtime parameters
    var parameters = new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code",
        ["client_id"] = _config.ClientId,           // ✅ From factory
        ["client_secret"] = _config.ClientSecret,   // ✅ From factory
        ["code"] = authorizationCode,               // ✅ From runtime
        ["redirect_uri"] = redirectUri,             // ✅ From runtime
        ["code_verifier"] = codeVerifier            // ✅ From runtime
    };
    
    return await MakeTokenRequest(parameters, cancellationToken);
}
```

## Benefits Summary

### For Developers
- **Clear API**: Factory configures, interface executes
- **Type Safety**: Compile-time validation of configuration
- **Intellisense**: Better IDE support with separated concerns
- **Testability**: Easy to mock factory vs interface behaviors

### For Security
- **Credential Isolation**: Secrets configured once, not passed around
- **Audit Trail**: Clear separation of setup vs usage
- **Least Privilege**: Runtime methods only get necessary data

### For Maintenance
- **Single Responsibility**: Each component has one clear purpose
- **Extensibility**: Add new flows without changing existing interface
- **Backwards Compatibility**: Factory changes don't affect interface usage

## Real-World Usage Examples

### Enterprise Application
```csharp
// Configuration in startup/DI container
services.AddSingleton<IAuthClient>(provider =>
    AuthClientFactory.CreateBuilder(authConfig.ServerUrl, authConfig.ClientId)
        .WithClientCredentialsFlow(authConfig.ClientSecret)
        .WithJwtBearerFlow(authConfig.PrivateKeyPath, authConfig.KeyId)
        .WithDefaultScopes("api.read", "api.write")
        .WithTimeout(30000)
        .Build());

// Usage in business logic
public class ApiService
{
    public async Task<Data> GetDataAsync()
    {
        var token = await _authClient.GetValidTokenAsync();  // ✅ Simple, no config needed
        return await _httpClient.GetAsync("/api/data", token);
    }
}
```

### Multi-Tenant SaaS
```csharp
// Different clients for different tenants
var tenantClients = tenants.ToDictionary(
    tenant => tenant.Id,
    tenant => AuthClientFactory.CreateBuilder(tenant.AuthServer, tenant.ClientId)
        .WithAuthorizationCodeFlow(tenant.ClientSecret)
        .WithDefaultScopes(tenant.DefaultScopes)
        .Build());

// Runtime usage varies per tenant
foreach (var user in users)
{
    var client = tenantClients[user.TenantId];
    var result = await client.AuthenticateAuthorizationCodeAsync(
        user.AuthCode, 
        user.RedirectUri, 
        user.CodeVerifier);
}
```

This design provides a clean, secure, and maintainable approach to OAuth2 authentication that scales from simple applications to complex enterprise scenarios.
