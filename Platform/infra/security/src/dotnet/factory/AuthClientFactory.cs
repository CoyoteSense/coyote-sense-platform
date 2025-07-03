using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Http;
using Coyote.Infra.Security.Auth.Modes.Real;
using Coyote.Infra.Security.Auth.Modes.Mock;
using Coyote.Infra.Security.Auth.Modes.Debug;
using Coyote.Infra.Security.Auth.Options;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Interface for authentication client factory
/// </summary>
public interface IAuthClientFactory
{
    IAuthClient CreateClient();
    IAuthClient CreateAuthClientForMode(RuntimeMode mode);
    RuntimeMode GetCurrentMode();
}

/// <summary>
/// Default implementation of authentication client factory
/// </summary>
public class AuthClientFactory : IAuthClientFactory
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptions<AuthClientModeOptions> _modeOptions;
    private readonly IOptions<AuthClientOptions> _authOptions;
    private readonly ILogger<AuthClientFactory> _logger;

    public AuthClientFactory(
        IServiceProvider serviceProvider,
        IOptions<AuthClientModeOptions> modeOptions,
        IOptions<AuthClientOptions> authOptions,
        ILogger<AuthClientFactory> logger)
    {
        _serviceProvider = serviceProvider;
        _modeOptions = modeOptions;
        _authOptions = authOptions;
        _logger = logger;
    }

    public IAuthClient CreateClient()
    {
        return CreateAuthClientForMode(GetCurrentMode());
    }

    public IAuthClient CreateAuthClientForMode(RuntimeMode mode)
    {
        _logger.LogDebug("Creating Auth client for mode: {Mode}", mode);
        
        return mode switch
        {
            RuntimeMode.Testing => CreateMockClient(),
            RuntimeMode.Production => CreateRealClient(),
            RuntimeMode.Debug => CreateDebugClient(),
            // For unimplemented modes, fall back to real implementation
            RuntimeMode.Recording => CreateRealClient(),
            RuntimeMode.Replay => CreateRealClient(),
            RuntimeMode.Simulation => CreateMockClient(),
            _ => CreateRealClient()
        };
    }

    public RuntimeMode GetCurrentMode()
    {
        // Check environment variables first
        var envMode = Environment.GetEnvironmentVariable("COYOTE_RUNTIME_MODE") 
                     ?? Environment.GetEnvironmentVariable("MODE");
        
        if (!string.IsNullOrEmpty(envMode) && 
            Enum.TryParse<RuntimeMode>(envMode, true, out var parsedMode))
        {
            return parsedMode;
        }
        
        // Fall back to configuration
        return _modeOptions.Value.Mode;
    }

    /// <summary>
    /// Create authentication client with specific options
    /// </summary>
    public IAuthClient CreateClient(AuthClientOptions options, ILogger logger)
    {
        return new RealAuthClient(options, (ILogger<RealAuthClient>)logger);
    }

    private IAuthClient CreateMockClient()
    {
        var logger = _serviceProvider.GetService<ILogger<MockAuthClient>>() ?? 
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<MockAuthClient>.Instance;
        return new MockAuthClient(_authOptions.Value, logger);
    }

    private IAuthClient CreateRealClient()
    {
        var logger = _serviceProvider.GetService<ILogger<RealAuthClient>>() ?? 
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<RealAuthClient>.Instance;
        return new RealAuthClient(_authOptions.Value, logger);
    }

    private IAuthClient CreateDebugClient()
    {
        var logger = _serviceProvider.GetService<ILogger<DebugAuthClient>>() ?? 
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<DebugAuthClient>.Instance;
        return new DebugAuthClient(_authOptions.Value, logger, _serviceProvider);
    }

    // Static factory methods
    
    /// <summary>
    /// Static helper method for tests - create from AuthClientOptions
    /// </summary>
    public static IAuthClient CreateFromOptions(AuthClientOptions options)
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));

        var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
        var logger = loggerFactory.CreateLogger<RealAuthClient>();
        
        return new RealAuthClient(options, logger);
    }

    /// <summary>
    /// Static helper method to create JWT Bearer client
    /// </summary>
    public static IAuthClient CreateJwtBearerClient(string serverUrl, string keyPath, List<string>? scopes = null, string? audience = null)
    {
        var options = new AuthClientOptions
        {
            ServerUrl = serverUrl,
            ClientId = "jwt-client",
            JwtSigningKeyPath = keyPath,
            JwtIssuer = audience ?? "coyotesense.io",
            JwtAudience = audience,
            DefaultScopes = scopes ?? new List<string> { "read", "write" },
            TimeoutMs = 30000,
            AutoRefresh = true
        };

        var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
        var logger = loggerFactory.CreateLogger<RealAuthClient>();
        
        return new RealAuthClient(options, logger);
    }

    /// <summary>
    /// Static helper method to create Client Credentials client
    /// </summary>
    public static IAuthClient CreateClientCredentialsClient(string serverUrl, string clientId, string clientSecret, List<string>? scopes = null)
    {
        var options = new AuthClientOptions
        {
            ServerUrl = serverUrl,
            ClientId = clientId,
            ClientSecret = clientSecret,
            DefaultScopes = scopes ?? new List<string> { "read", "write" },
            TimeoutMs = 30000,
            AutoRefresh = true
        };

        var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
        var logger = loggerFactory.CreateLogger<RealAuthClient>();
        
        return new RealAuthClient(options, logger);
    }

    /// <summary>
    /// Static helper method to create Authorization Code client
    /// </summary>
    public static IAuthClient CreateAuthorizationCodeClient(string serverUrl, string clientId, string redirectUri, List<string>? scopes = null)
    {
        var options = new AuthClientOptions
        {
            ServerUrl = serverUrl,
            ClientId = clientId,
            RedirectUri = redirectUri,
            DefaultScopes = scopes ?? new List<string> { "read", "write" },
            TimeoutMs = 30000,
            AutoRefresh = true
        };

        var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
        var logger = loggerFactory.CreateLogger<RealAuthClient>();
        
        return new RealAuthClient(options, logger);
    }

    /// <summary>
    /// Static helper method to create an auth client with secure credentials
    /// </summary>
    public static IAuthClient CreateWithSecureCredentials(string serverUrl, string credentialPath, List<string>? scopes = null)
    {
        var options = new AuthClientOptions
        {
            ServerUrl = serverUrl,
            ClientId = "test-client",
            DefaultScopes = scopes ?? new List<string> { "read", "write" },
            TimeoutMs = 30000,
            AutoRefresh = true
        };

        var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
        var logger = loggerFactory.CreateLogger<RealAuthClient>();
        
        return new RealAuthClient(options, logger);
    }

    /// <summary>
    /// Get default HTTP client for authentication
    /// </summary>
    public static HttpClient GetDefaultHttpClient()
    {
        return new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>
    /// Set HTTP client factory for authentication
    /// </summary>
    public static void SetHttpClientFactory(IHttpClientFactory factory)
    {
        // Store factory reference for later use
        _httpClientFactory = factory;
    }

    private static IHttpClientFactory? _httpClientFactory;
}

/// <summary>
/// Extension methods for dependency injection registration
/// </summary>
public static class AuthServiceCollectionExtensions
{
    /// <summary>
    /// Register authentication client infrastructure with DI container
    /// </summary>
    public static IServiceCollection AddCoyoteAuthClient(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Register configuration options
        services.Configure<AuthClientOptions>(
            configuration.GetSection("Coyote:Auth"));
        services.Configure<AuthClientModeOptions>(
            configuration.GetSection("Coyote:Auth:Mode"));

        // Register factory
        services.AddSingleton<IAuthClientFactory, AuthClientFactory>();

        // Register all mode implementations
        services.AddTransient<RealAuthClient>();
        services.AddTransient<MockAuthClient>();
        services.AddTransient<DebugAuthClient>();
        
        // Register the main service
        services.AddTransient<IAuthClient>(provider =>
        {
            var factory = provider.GetRequiredService<IAuthClientFactory>();
            return factory.CreateClient();
        });

        return services;
    }

    /// <summary>
    /// Register authentication client infrastructure with explicit mode configuration
    /// </summary>
    public static IServiceCollection AddCoyoteAuthClient(
        this IServiceCollection services,
        Action<AuthClientOptions>? configureAuth = null,
        Action<AuthClientModeOptions>? configureMode = null)
    {
        // Register configuration options
        if (configureAuth != null)
        {
            services.Configure(configureAuth);
        }
        
        if (configureMode != null)
        {
            services.Configure(configureMode);
        }

        // Register factory
        services.AddSingleton<IAuthClientFactory, AuthClientFactory>();

        // Register all mode implementations
        services.AddTransient<RealAuthClient>();
        services.AddTransient<MockAuthClient>();
        services.AddTransient<DebugAuthClient>();
        
        // Register the main service
        services.AddTransient<IAuthClient>(provider =>
        {
            var factory = provider.GetRequiredService<IAuthClientFactory>();
            return factory.CreateClient();
        });

        return services;
    }
}
