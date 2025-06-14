using System;
using System.Threading;
using System.Threading.Tasks;
using Coyote.Infra.Security.Auth.Clients;
using Coyote.Infra.Security.Auth.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Coyote.Infra.Security.Auth.Factory;

/// <summary>
/// Factory for creating SecureStoreClient instances with various configuration patterns
/// Provides multiple creation methods to support different integration scenarios
/// </summary>
public static class SecureStoreClientFactory
{
    /// <summary>
    /// Create SecureStoreClient with integrated IAuthClient
    /// Recommended for most scenarios - provides automatic token management
    /// </summary>
    public static ISecureStoreClient CreateWithAuthClient(
        SecureStoreOptions options,
        IAuthClient authClient,
        ILogger<SecureStoreClient>? logger = null)
    {
        return new SecureStoreClient(options, authClient, logger);
    }

    /// <summary>
    /// Create SecureStoreClient with external token provider
    /// Use when you need loose coupling or custom token management
    /// </summary>
    public static ISecureStoreClient CreateWithTokenProvider(
        SecureStoreOptions options,
        Func<CancellationToken, Task<string?>> tokenProvider,
        ILogger<SecureStoreClient>? logger = null)
    {
        return new SecureStoreClient(options, tokenProvider, logger);
    }

    /// <summary>
    /// Create SecureStoreClient from IOptions pattern (for DI scenarios)
    /// </summary>
    public static ISecureStoreClient CreateFromOptions(
        IOptions<SecureStoreOptions> options,
        IAuthClient authClient,
        ILogger<SecureStoreClient>? logger = null)
    {
        return new SecureStoreClient(options.Value, authClient, logger);
    }    /// <summary>
    /// Create SecureStoreClient with integrated authentication
    /// Creates both the auth client and secure store client
    /// </summary>
    public static ISecureStoreClient CreateWithIntegratedAuth(
        SecureStoreAuthOptions options,
        ILogger<SecureStoreClient>? logger = null)
    {
        if (options.AuthClientConfig == null)
            throw new ArgumentException("AuthClientConfig is required when using integrated auth", nameof(options));

        // TODO: Create the auth client once AuthClientFactory is available
        throw new NotImplementedException("Integrated auth not yet implemented - use CreateWithTokenProvider instead");
        
        // var authClient = AuthClientFactory.CreateFromConfig(options.AuthClientConfig);
        // return new SecureStoreClient(options, authClient, logger);
    }

    /// <summary>
    /// Create SecureStoreClient from configuration file
    /// Loads configuration from JSON/XML and creates appropriate client
    /// </summary>
    public static ISecureStoreClient CreateFromConfig(
        string configFilePath,
        ILogger<SecureStoreClient>? logger = null)
    {
        // Load configuration from file
        var config = LoadConfigFromFile(configFilePath);
        
        if (config.UseIntegratedAuth && config.AuthClientConfig != null)
        {
            return CreateWithIntegratedAuth(config, logger);
        }
        
        throw new InvalidOperationException("Configuration must specify integrated auth or provide external auth client");
    }

    /// <summary>
    /// Create SecureStoreClient from environment variables
    /// Convenient for containerized environments
    /// </summary>
    public static ISecureStoreClient CreateFromEnvironment(
        ILogger<SecureStoreClient>? logger = null)
    {
        var options = new SecureStoreAuthOptions
        {
            ServerUrl = Environment.GetEnvironmentVariable("KEYVAULT_URL") 
                ?? throw new InvalidOperationException("KEYVAULT_URL environment variable is required"),
            
            ApiVersion = Environment.GetEnvironmentVariable("KEYVAULT_API_VERSION") ?? "v1",
            
            TimeoutMs = int.TryParse(Environment.GetEnvironmentVariable("KEYVAULT_TIMEOUT_MS"), out var timeout) 
                ? timeout : 30000,
            
            MaxRetryAttempts = int.TryParse(Environment.GetEnvironmentVariable("KEYVAULT_MAX_RETRIES"), out var retries) 
                ? retries : 3,
            
            VerifySsl = Environment.GetEnvironmentVariable("KEYVAULT_VERIFY_SSL") != "false",
            
            CaCertPath = Environment.GetEnvironmentVariable("KEYVAULT_CA_CERT_PATH"),
            
            UseMutualTls = Environment.GetEnvironmentVariable("KEYVAULT_USE_MTLS") == "true",
            ClientCertPath = Environment.GetEnvironmentVariable("KEYVAULT_CLIENT_CERT_PATH"),
            ClientKeyPath = Environment.GetEnvironmentVariable("KEYVAULT_CLIENT_KEY_PATH"),
            
            DefaultNamespace = Environment.GetEnvironmentVariable("KEYVAULT_DEFAULT_NAMESPACE"),
            
            UseIntegratedAuth = Environment.GetEnvironmentVariable("KEYVAULT_USE_INTEGRATED_AUTH") != "false",
        };

        // Create auth client config from environment
        if (options.UseIntegratedAuth)
        {
            options.AuthClientConfig = CreateAuthConfigFromEnvironment();
        }

        return CreateWithIntegratedAuth(options, logger);
    }

    /// <summary>
    /// Builder pattern for fluent configuration
    /// Provides a fluent API for complex configurations
    /// </summary>
    public static SecureStoreClientBuilder CreateBuilder(string serverUrl)
    {
        return new SecureStoreClientBuilder(serverUrl);
    }

    private static SecureStoreAuthOptions LoadConfigFromFile(string configFilePath)
    {
        // In a real implementation, you'd load from JSON/XML file
        // For now, return a basic configuration
        throw new NotImplementedException("Configuration file loading not yet implemented");
    }

    private static AuthClientConfig CreateAuthConfigFromEnvironment()
    {
        var authServerUrl = Environment.GetEnvironmentVariable("AUTH_SERVER_URL") 
            ?? throw new InvalidOperationException("AUTH_SERVER_URL environment variable is required");
        
        var clientId = Environment.GetEnvironmentVariable("AUTH_CLIENT_ID") 
            ?? throw new InvalidOperationException("AUTH_CLIENT_ID environment variable is required");        return new AuthClientConfig
        {
            AuthMode = ParseAuthMode(Environment.GetEnvironmentVariable("AUTH_MODE")),
            ServerUrl = authServerUrl,
            ClientId = clientId,
            ClientSecret = Environment.GetEnvironmentVariable("AUTH_CLIENT_SECRET"),
            ClientCertPath = Environment.GetEnvironmentVariable("AUTH_CLIENT_CERT_PATH"),
            ClientKeyPath = Environment.GetEnvironmentVariable("AUTH_CLIENT_KEY_PATH"),
            DefaultScopes = ParseScopes(Environment.GetEnvironmentVariable("AUTH_SCOPES")),
            TimeoutMs = int.TryParse(Environment.GetEnvironmentVariable("AUTH_TIMEOUT_MS"), out var authTimeout) 
                ? authTimeout : 30000,
            MaxRetryAttempts = int.TryParse(Environment.GetEnvironmentVariable("AUTH_MAX_RETRIES"), out var authRetries) 
                ? authRetries : 3,
            VerifySsl = Environment.GetEnvironmentVariable("AUTH_VERIFY_SSL") != "false"
        };
    }

    private static AuthMode ParseAuthMode(string? authMode)
    {        return authMode?.ToLowerInvariant() switch
        {
            "client_credentials" => AuthMode.ClientCredentials,
            "jwt_bearer" => AuthMode.JwtBearer,
            "mtls" or "client_credentials_mtls" => AuthMode.ClientCredentialsMtls,
            "authorization_code" => AuthMode.AuthorizationCode,
            _ => AuthMode.ClientCredentials
        };
    }

    private static System.Collections.Generic.List<string> ParseScopes(string? scopes)
    {
        if (string.IsNullOrWhiteSpace(scopes))
            return new System.Collections.Generic.List<string> { "keyvault.read" };

        return new System.Collections.Generic.List<string>(scopes.Split(',', StringSplitOptions.RemoveEmptyEntries));
    }
}

/// <summary>
/// Builder class for fluent SecureStoreClient configuration
/// </summary>
public class SecureStoreClientBuilder
{
    private readonly SecureStoreAuthOptions _options;
    private IAuthClient? _authClient;
    private Func<CancellationToken, Task<string?>>? _tokenProvider;
    private ILogger<SecureStoreClient>? _logger;

    internal SecureStoreClientBuilder(string serverUrl)
    {
        _options = new SecureStoreAuthOptions
        {
            ServerUrl = serverUrl,
            UseIntegratedAuth = false
        };
    }

    /// <summary>
    /// Configure API version
    /// </summary>
    public SecureStoreClientBuilder WithApiVersion(string apiVersion)
    {
        _options.ApiVersion = apiVersion;
        return this;
    }

    /// <summary>
    /// Configure timeout settings
    /// </summary>
    public SecureStoreClientBuilder WithTimeout(int timeoutMs)
    {
        _options.TimeoutMs = timeoutMs;
        return this;
    }

    /// <summary>
    /// Configure retry settings
    /// </summary>
    public SecureStoreClientBuilder WithRetry(int maxAttempts, int backoffMs = 1000)
    {
        _options.MaxRetryAttempts = maxAttempts;
        _options.RetryBackoffMs = backoffMs;
        return this;
    }

    /// <summary>
    /// Configure SSL/TLS settings
    /// </summary>
    public SecureStoreClientBuilder WithTls(bool verifySsl = true, string? caCertPath = null)
    {
        _options.VerifySsl = verifySsl;
        _options.CaCertPath = caCertPath;
        return this;
    }

    /// <summary>
    /// Configure mutual TLS
    /// </summary>
    public SecureStoreClientBuilder WithMutualTls(string clientCertPath, string clientKeyPath)
    {
        _options.UseMutualTls = true;
        _options.ClientCertPath = clientCertPath;
        _options.ClientKeyPath = clientKeyPath;
        return this;
    }

    /// <summary>
    /// Configure default namespace for secrets
    /// </summary>
    public SecureStoreClientBuilder WithDefaultNamespace(string defaultNamespace)
    {
        _options.DefaultNamespace = defaultNamespace;
        return this;
    }

    /// <summary>
    /// Use existing IAuthClient for authentication
    /// </summary>
    public SecureStoreClientBuilder WithAuthClient(IAuthClient authClient)
    {
        _authClient = authClient;
        _options.UseIntegratedAuth = true;
        return this;
    }

    /// <summary>
    /// Use external token provider
    /// </summary>
    public SecureStoreClientBuilder WithTokenProvider(Func<CancellationToken, Task<string?>> tokenProvider)
    {
        _tokenProvider = tokenProvider;
        _options.UseIntegratedAuth = false;
        return this;
    }

    /// <summary>
    /// Configure integrated authentication
    /// </summary>
    public SecureStoreClientBuilder WithIntegratedAuth(Action<AuthClientConfig> configureAuth)
    {
        _options.AuthClientConfig = new AuthClientConfig();
        configureAuth(_options.AuthClientConfig);
        _options.UseIntegratedAuth = true;
        return this;
    }

    /// <summary>
    /// Configure logging
    /// </summary>
    public SecureStoreClientBuilder WithLogger(ILogger<SecureStoreClient> logger)
    {
        _logger = logger;
        return this;
    }

    /// <summary>
    /// Enable/disable logging
    /// </summary>
    public SecureStoreClientBuilder WithLogging(bool enableLogging = true)
    {
        _options.EnableLogging = enableLogging;
        return this;
    }

    /// <summary>
    /// Enable/disable metrics
    /// </summary>
    public SecureStoreClientBuilder WithMetrics(bool enableMetrics = true)
    {
        _options.EnableMetrics = enableMetrics;
        return this;
    }

    /// <summary>
    /// Add custom headers
    /// </summary>
    public SecureStoreClientBuilder WithCustomHeaders(System.Collections.Generic.Dictionary<string, string> headers)
    {
        foreach (var header in headers)
        {
            _options.CustomHeaders[header.Key] = header.Value;
        }
        return this;
    }

    /// <summary>
    /// Build the SecureStoreClient
    /// </summary>
    public ISecureStoreClient Build()
    {
        _options.Validate();

        if (_authClient != null)
        {
            return new SecureStoreClient(_options, _authClient, _logger);
        }

        if (_tokenProvider != null)
        {
            return new SecureStoreClient(_options, _tokenProvider, _logger);
        }        if (_options.UseIntegratedAuth && _options.AuthClientConfig != null)
        {
            // TODO: Enable once AuthClientFactory is available
            throw new NotImplementedException("Integrated auth not yet implemented - use WithTokenProvider instead");
            // var authClient = AuthClientFactory.CreateFromConfig(_options.AuthClientConfig);
            // return new SecureStoreClient(_options, authClient, _logger);
        }

        throw new InvalidOperationException("Must specify either an IAuthClient, token provider, or integrated auth configuration");
    }
}
