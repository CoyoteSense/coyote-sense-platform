using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Security;

namespace Coyote.Infra.Security.Examples;

/// <summary>
/// Comprehensive examples showing enhanced authentication client patterns
/// Demonstrates both legacy factory methods and new options-based approaches
/// </summary>
public class EnhancedAuthClientExamples
{
    private const string ServerUrl = "https://auth.coyotesense.io";
    private const string ClientId = "my-service-client";

    /// <summary>
    /// Example: New Options Pattern for mTLS (RECOMMENDED)
    /// Clean, validated, and maintainable approach
    /// </summary>
    public static async Task MtlsOptionsPatternExample()
    {
        Console.WriteLine("\n=== Enhanced mTLS Options Pattern Example ===");

        // Define configuration using options pattern
        var mtlsOptions = new MtlsOptions
        {
            ServerUrl = ServerUrl,
            ClientId = ClientId,
            ClientCertPath = "/opt/coyote/certs/client.crt",
            ClientKeyPath = "/opt/coyote/certs/client.key",
            CaCertPath = "/opt/coyote/certs/ca.crt",
            DefaultScopes = new List<string> { "keyvault.read", "keyvault.write" },
            AutoRefresh = true,
            RefreshBufferSeconds = 300,
            TimeoutMs = 30000,
            MaxRetryAttempts = 3,
            VerifySsl = true
        };

        // Create client using options (automatic validation)
        using var client = AuthClientFactory.CreateFromOptions(
            mtlsOptions,
            tokenStorage: new ConsoleTokenStorage(),
            logger: new ConsoleAuthLogger("mTLS-Options")
        );

        // Authenticate
        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"✅ mTLS authentication successful!");
            Console.WriteLine($"Token: {result.Token!.AccessToken[..20]}...");
            Console.WriteLine($"Expires: {result.Token.ExpiresAt}");
            Console.WriteLine($"Scopes: {string.Join(", ", result.Token.Scopes)}");
        }
        else
        {
            Console.WriteLine($"❌ mTLS authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
        }
    }

    /// <summary>
    /// Example: Legacy Factory Method (LEGACY - Consider migrating)
    /// Shows the old approach for comparison
    /// </summary>
    public static async Task MtlsLegacyFactoryExample()
    {
        Console.WriteLine("\n=== Legacy mTLS Factory Example ===");

        // Legacy approach with many parameters
        #pragma warning disable CS0618 // Type or member is obsolete
        using var client = AuthClientFactory.CreateMtlsClient(
            serverUrl: ServerUrl,
            clientId: ClientId,
            clientCertPath: "/opt/coyote/certs/client.crt",
            clientKeyPath: "/opt/coyote/certs/client.key",
            defaultScopes: new List<string> { "keyvault.read", "keyvault.write" },
            logger: new ConsoleAuthLogger("mTLS-Legacy")
        );
        #pragma warning restore CS0618

        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"✅ Legacy mTLS authentication successful!");
        }
        else
        {
            Console.WriteLine($"❌ Legacy mTLS authentication failed: {result.ErrorCode}");
        }
    }

    /// <summary>
    /// Example: Secure Credential Provider
    /// Enhanced security for handling sensitive credentials
    /// </summary>
    public static async Task SecureCredentialExample()
    {
        Console.WriteLine("\n=== Secure Credential Provider Example ===");

        // Create secure credential provider
        using var credentialProvider = new SecureCredentialProvider();
        
        // Load secret from environment or secure store
        var clientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? "my-secret-key";
        credentialProvider.SetClientSecret(clientSecret);

        // Create base configuration
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = ServerUrl,
            ClientId = ClientId,
            DefaultScopes = new List<string> { "api.read" }
        };

        // Create client with secure credentials
        using var client = AuthClientFactory.CreateWithSecureCredentials(
            config,
            credentialProvider,
            logger: new ConsoleAuthLogger("Secure")
        );

        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"✅ Secure credential authentication successful!");
        }
        else
        {
            Console.WriteLine($"❌ Secure credential authentication failed: {result.ErrorCode}");
        }
    }

    /// <summary>
    /// Example: Microsoft Options Pattern Integration
    /// For dependency injection scenarios
    /// </summary>
    public static async Task OptionsPatternDIExample()
    {
        Console.WriteLine("\n=== Options Pattern DI Example ===");

        // Simulate IOptions<T> from dependency injection
        var jwtOptions = new JwtBearerOptions
        {
            ServerUrl = ServerUrl,
            ClientId = ClientId,
            JwtSigningKeyPath = "/opt/coyote/keys/private.pem",
            JwtIssuer = "coyote-service",
            JwtAudience = "auth.coyotesense.io",
            JwtAlgorithm = "RS256",
            DefaultScopes = new List<string> { "jwt.bearer" },
            AutoRefresh = true
        };

        var options = Options.Create(jwtOptions);

        // Create client using IOptions pattern
        using var client = AuthClientFactory.CreateFromOptions(
            options,
            logger: new ConsoleAuthLogger("JWT-DI")
        );

        var result = await client.AuthenticateJwtBearerAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"✅ JWT Bearer DI authentication successful!");
        }
        else
        {
            Console.WriteLine($"❌ JWT Bearer DI authentication failed: {result.ErrorCode}");
        }
    }

    /// <summary>
    /// Example: Builder Pattern (Fluent API)
    /// For complex configurations
    /// </summary>
    public static async Task BuilderPatternExample()
    {
        Console.WriteLine("\n=== Builder Pattern Example ===");

        // Use fluent builder API
        using var client = AuthClientFactory.CreateBuilder(ServerUrl, ClientId)
            .WithClientSecret("my-client-secret")
            .WithDefaultScopes("api.read", "api.write")
            .WithAutoRefresh(enabled: true, bufferSeconds: 600)
            .WithTimeout(45000)
            .WithSslVerification(true)
            .WithMaxRetryAttempts(5)
            .WithLogger(new ConsoleAuthLogger("Builder"))
            .Build();

        var result = await client.AuthenticateClientCredentialsAsync();
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"✅ Builder pattern authentication successful!");
        }
        else
        {
            Console.WriteLine($"❌ Builder pattern authentication failed: {result.ErrorCode}");
        }
    }

    /// <summary>
    /// Example: Multiple Authentication Flows
    /// Showing different authentication patterns
    /// </summary>
    public static async Task MultipleFlowsExample()
    {
        Console.WriteLine("\n=== Multiple Authentication Flows Example ===");

        // Client Credentials Flow
        var clientCredOptions = new ClientCredentialsOptions
        {
            ServerUrl = ServerUrl,
            ClientId = ClientId,
            ClientSecret = "my-secret",
            DefaultScopes = new List<string> { "basic.read" }
        };

        using var clientCredClient = AuthClientFactory.CreateFromOptions(clientCredOptions);
        var clientCredResult = await clientCredClient.AuthenticateClientCredentialsAsync();
        Console.WriteLine($"Client Credentials: {(clientCredResult.IsSuccess ? "✅ Success" : "❌ Failed")}");

        // Authorization Code Flow (for web applications)
        var authCodeOptions = new AuthorizationCodeOptions
        {
            ServerUrl = ServerUrl,
            ClientId = ClientId,
            RedirectUri = "https://myapp.example.com/callback",
            UsePkce = true,
            DefaultScopes = new List<string> { "openid", "profile" }
        };

        using var authCodeClient = AuthClientFactory.CreateFromOptions(authCodeOptions);
        
        // For Authorization Code, you'd typically redirect user to authorization URL
        var authUrl = await authCodeClient.GetAuthorizationUrlAsync(
            scopes: new List<string> { "openid", "profile" },
            state: "random-state-value"
        );
        Console.WriteLine($"Authorization URL: {authUrl}");
    }

    /// <summary>
    /// Run all examples
    /// </summary>
    public static async Task RunAllExamples()
    {
        Console.WriteLine("🚀 Running Enhanced AuthClient Examples");
        Console.WriteLine("==========================================");

        try
        {
            await MtlsOptionsPatternExample();
            await MtlsLegacyFactoryExample();
            await SecureCredentialExample();
            await OptionsPatternDIExample();
            await BuilderPatternExample();
            await MultipleFlowsExample();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Example failed: {ex.Message}");
        }

        Console.WriteLine("\n✅ Examples completed!");
    }
}

/// <summary>
/// Simple console-based token storage for examples
/// </summary>
public class ConsoleTokenStorage : IAuthTokenStorage
{
    public Task<AuthToken?> LoadTokenAsync(string key)
    {
        Console.WriteLine($"📥 Loading token for key: {key}");
        return Task.FromResult<AuthToken?>(null);
    }

    public Task SaveTokenAsync(string key, AuthToken token)
    {
        Console.WriteLine($"💾 Saving token for key: {key} (expires: {token.ExpiresAt})");
        return Task.CompletedTask;
    }

    public Task DeleteTokenAsync(string key)
    {
        Console.WriteLine($"🗑️ Deleting token for key: {key}");
        return Task.CompletedTask;
    }
}

/// <summary>
/// Simple console-based logger for examples
/// </summary>
public class ConsoleAuthLogger : IAuthLogger
{
    private readonly string _prefix;

    public ConsoleAuthLogger(string prefix)
    {
        _prefix = prefix;
    }

    public void LogInfo(string message) => Console.WriteLine($"[{_prefix}] ℹ️ {message}");
    public void LogWarning(string message) => Console.WriteLine($"[{_prefix}] ⚠️ {message}");
    public void LogError(string message) => Console.WriteLine($"[{_prefix}] ❌ {message}");
    public void LogDebug(string message) => Console.WriteLine($"[{_prefix}] 🔍 {message}");
}
