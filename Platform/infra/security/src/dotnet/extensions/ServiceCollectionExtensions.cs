using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Modes.Real;

namespace Coyote.Infra.Security.Extensions;

/// <summary>
/// Service collection extensions for authentication services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add authentication client with client credentials flow
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configure">Configuration action</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddAuthClientWithClientCredentials(
        this IServiceCollection services,
        Action<ClientCredentialsOptions> configure)
    {
        if (configure == null)
            throw new ArgumentNullException(nameof(configure));

        var options = new ClientCredentialsOptions();
        configure(options);
        options.Validate();

        services.AddSingleton(options);
        services.AddSingleton<IAuthClient>(provider =>
        {
            var logger = provider.GetService<ILogger<AuthClient>>() ?? 
                        provider.GetRequiredService<ILoggerFactory>().CreateLogger<AuthClient>();
            var authOptions = options.ToAuthClientConfig().ToAuthClientOptions();
            return new AuthClient(authOptions, logger);
        });

        return services;
    }

    /// <summary>
    /// Add authentication client with JWT Bearer flow
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configure">Configuration action</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddAuthClientWithJwtBearer(
        this IServiceCollection services,
        Action<JwtBearerOptions> configure)
    {
        if (configure == null)
            throw new ArgumentNullException(nameof(configure));

        var options = new JwtBearerOptions();
        configure(options);
        options.Validate();

        services.AddSingleton(options);
        services.AddSingleton<IAuthClient>(provider =>
        {
            var logger = provider.GetService<ILogger<AuthClient>>() ?? 
                        provider.GetRequiredService<ILoggerFactory>().CreateLogger<AuthClient>();
            var authOptions = options.ToAuthClientConfig().ToAuthClientOptions();
            return new AuthClient(authOptions, logger);
        });

        return services;
    }

    /// <summary>
    /// Add comprehensive authentication services including client pool and secure store
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services)
    {        // Add logging if not already added
        services.AddLogging();

        // Add secure store client
        services.AddSingleton<ISecureStoreClient>(provider =>
        {
            var options = new SecureStoreOptions
            {
                ServerUrl = "https://keyvault.coyotesense.io",
                ApiVersion = "v1",
                TimeoutMs = 30000,
                MaxRetryAttempts = 3,
                VerifySsl = true
            };
            
            // Create auth client directly
            var authOptions = new AuthClientOptions
            {
                ServerUrl = "https://auth.coyotesense.io",
                ClientId = "default-client",
                DefaultScopes = new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };
            var authLogger = provider.GetRequiredService<ILogger<RealAuthClient>>();
            var authClient = new RealAuthClient(authOptions, authLogger);
            var logger = provider.GetService<ILogger<SecureStoreClient>>();
            
            return SecureStoreClientFactory.CreateWithAuthClient(options, authClient, logger);
        });

        return services;
    }
}

/// <summary>
/// Options for configuring authentication services
/// </summary>
public class AuthenticationServicesOptions
{
    /// <summary>
    /// Authentication server URL
    /// </summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>
    /// Secure store server URL (defaults to ServerUrl if not specified)
    /// </summary>
    public string? SecureStoreUrl { get; set; }

    /// <summary>
    /// Client identifier
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Client secret
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Maximum size of the auth client pool
    /// </summary>
    public int MaxPoolSize { get; set; } = 10;

    /// <summary>
    /// Request timeout in milliseconds
    /// </summary>
    public int TimeoutMs { get; set; } = 30000;
}
