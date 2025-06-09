using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Clients;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Factory;

namespace Coyote.Infra.Security.Auth.Extensions;

/// <summary>
/// Extension methods for registering SecureStoreClient with dependency injection
/// Provides clean integration with Microsoft.Extensions.DependencyInjection
/// </summary>
public static class SecureStoreServiceCollectionExtensions
{
    /// <summary>
    /// Add SecureStoreClient with integrated authentication
    /// Registers both IAuthClient and ISecureStoreClient
    /// </summary>
    public static IServiceCollection AddSecureStoreClientWithAuth(
        this IServiceCollection services,
        Action<SecureStoreAuthOptions> configureOptions)
    {
        services.Configure(configureOptions);
        
        services.AddSingleton<ISecureStoreClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecureStoreAuthOptions>>().Value;
            var logger = provider.GetService<ILogger<SecureStoreClient>>();
            
            return SecureStoreClientFactory.CreateWithIntegratedAuth(options, logger);
        });

        return services;
    }

    /// <summary>
    /// Add SecureStoreClient with existing IAuthClient registration
    /// Use when you already have IAuthClient configured
    /// </summary>
    public static IServiceCollection AddSecureStoreClient(
        this IServiceCollection services,
        Action<SecureStoreOptions> configureOptions)
    {
        services.Configure(configureOptions);
        
        services.AddSingleton<ISecureStoreClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecureStoreOptions>>().Value;
            var authClient = provider.GetRequiredService<IAuthClient>();
            var logger = provider.GetService<ILogger<SecureStoreClient>>();
            
            return SecureStoreClientFactory.CreateWithAuthClient(options, authClient, logger);
        });

        return services;
    }

    /// <summary>
    /// Add SecureStoreClient with custom token provider
    /// Use for advanced scenarios with custom authentication
    /// </summary>
    public static IServiceCollection AddSecureStoreClientWithTokenProvider(
        this IServiceCollection services,
        Action<SecureStoreOptions> configureOptions,
        Func<IServiceProvider, Func<CancellationToken, Task<string?>>> tokenProviderFactory)
    {
        services.Configure(configureOptions);
        
        services.AddSingleton<ISecureStoreClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecureStoreOptions>>().Value;
            var tokenProvider = tokenProviderFactory(provider);
            var logger = provider.GetService<ILogger<SecureStoreClient>>();
            
            return SecureStoreClientFactory.CreateWithTokenProvider(options, tokenProvider, logger);
        });

        return services;
    }

    /// <summary>
    /// Add SecureStoreClient from configuration section
    /// Automatically binds configuration and registers services
    /// </summary>
    public static IServiceCollection AddSecureStoreClientFromConfiguration(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = "SecureStore")
    {
        var section = configuration.GetSection(sectionName);
        services.Configure<SecureStoreAuthOptions>(section);
        
        services.AddSingleton<ISecureStoreClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecureStoreAuthOptions>>().Value;
            var logger = provider.GetService<ILogger<SecureStoreClient>>();
            
            return SecureStoreClientFactory.CreateWithIntegratedAuth(options, logger);
        });

        return services;
    }

    /// <summary>
    /// Add SecureStoreClient with environment-based configuration
    /// Perfect for containerized applications
    /// </summary>
    public static IServiceCollection AddSecureStoreClientFromEnvironment(
        this IServiceCollection services)
    {
        services.AddSingleton<ISecureStoreClient>(provider =>
        {
            var logger = provider.GetService<ILogger<SecureStoreClient>>();
            return SecureStoreClientFactory.CreateFromEnvironment(logger);
        });

        return services;
    }

    /// <summary>
    /// Add SecureStoreClient with builder pattern configuration
    /// Provides fluent configuration within DI registration
    /// </summary>
    public static IServiceCollection AddSecureStoreClientWithBuilder(
        this IServiceCollection services,
        string serverUrl,
        Action<SecureStoreClientBuilder> configureBuilder)
    {
        services.AddSingleton<ISecureStoreClient>(provider =>
        {
            var builder = SecureStoreClientFactory.CreateBuilder(serverUrl);
            
            // Allow configuration callback to modify builder
            configureBuilder(builder);
            
            // Add logger if available
            var logger = provider.GetService<ILogger<SecureStoreClient>>();
            if (logger != null)
            {
                builder.WithLogger(logger);
            }
            
            return builder.Build();
        });

        return services;
    }

    /// <summary>
    /// Add SecureStoreClient with health checks
    /// Registers health check for the KeyVault connection
    /// </summary>
    public static IServiceCollection AddSecureStoreClientWithHealthChecks(
        this IServiceCollection services,
        Action<SecureStoreAuthOptions> configureOptions,
        string healthCheckName = "keyvault")
    {
        // Add the client
        services.AddSecureStoreClientWithAuth(configureOptions);
        
        // Add health check
        services.AddHealthChecks()
            .AddCheck<SecureStoreHealthCheck>(healthCheckName);
        
        return services;
    }

    /// <summary>
    /// Add multiple SecureStoreClient instances with different configurations
    /// Use for multi-tenant or multi-environment scenarios
    /// </summary>
    public static IServiceCollection AddNamedSecureStoreClient(
        this IServiceCollection services,
        string name,
        Action<SecureStoreAuthOptions> configureOptions)
    {
        services.Configure<SecureStoreAuthOptions>(name, configureOptions);
        
        // Register named service factory
        services.AddSingleton<ISecureStoreClientFactory>(provider =>
            new SecureStoreClientFactory(provider));
        
        return services;
    }
}

/// <summary>
/// Health check for SecureStoreClient
/// Monitors KeyVault connectivity and authentication
/// </summary>
public class SecureStoreHealthCheck : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    private readonly ISecureStoreClient _secureStoreClient;
    private readonly ILogger<SecureStoreHealthCheck> _logger;

    public SecureStoreHealthCheck(ISecureStoreClient secureStoreClient, ILogger<SecureStoreHealthCheck> logger)
    {
        _secureStoreClient = secureStoreClient ?? throw new ArgumentNullException(nameof(secureStoreClient));
        _logger = logger;
    }

    public async Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Test basic connectivity
            var isConnected = await _secureStoreClient.TestConnectionAsync(cancellationToken);
            if (!isConnected)
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy(
                    "KeyVault connection test failed");
            }

            // Get detailed health status
            var healthStatus = await _secureStoreClient.GetHealthStatusAsync(cancellationToken);
            if (healthStatus == null)
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Degraded(
                    "KeyVault health status unavailable");
            }

            if (!healthStatus.IsHealthy)
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy(
                    $"KeyVault reports unhealthy status: {healthStatus.Status}",
                    data: healthStatus.Details);
            }

            // Check authentication status
            if (!_secureStoreClient.IsAuthenticated)
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Degraded(
                    "KeyVault client is not authenticated");
            }

            return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy(
                "KeyVault is healthy and authenticated",
                data: healthStatus.Details);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "KeyVault health check failed");
            return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy(
                "KeyVault health check exception", ex);
        }
    }
}

/// <summary>
/// Factory for creating named SecureStoreClient instances
/// Supports multi-tenant scenarios
/// </summary>
public interface ISecureStoreClientFactory
{
    ISecureStoreClient CreateClient(string name);
}

public class SecureStoreClientFactory : ISecureStoreClientFactory
{
    private readonly IServiceProvider _serviceProvider;

    public SecureStoreClientFactory(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public ISecureStoreClient CreateClient(string name)
    {
        var optionsMonitor = _serviceProvider.GetRequiredService<IOptionsMonitor<SecureStoreAuthOptions>>();
        var options = optionsMonitor.Get(name);
        var logger = _serviceProvider.GetService<ILogger<SecureStoreClient>>();
        
        return Auth.Factory.SecureStoreClientFactory.CreateWithIntegratedAuth(options, logger);
    }
}

/// <summary>
/// Configuration extensions for easy setup
/// </summary>
public static class SecureStoreConfigurationExtensions
{
    /// <summary>
    /// Bind SecureStoreAuthOptions from configuration with validation
    /// </summary>
    public static SecureStoreAuthOptions BindSecureStoreOptions(this IConfiguration configuration, string sectionName = "SecureStore")
    {
        var options = new SecureStoreAuthOptions();
        configuration.GetSection(sectionName).Bind(options);
        
        // Validate configuration
        options.Validate();
        
        return options;
    }

    /// <summary>
    /// Get SecureStore configuration section with fallback values
    /// </summary>
    public static IConfigurationSection GetSecureStoreSection(this IConfiguration configuration, string sectionName = "SecureStore")
    {
        return configuration.GetSection(sectionName);
    }
}

/// <summary>
/// Hosted service for SecureStoreClient background operations
/// Handles token refresh and health monitoring
/// </summary>
public class SecureStoreBackgroundService : Microsoft.Extensions.Hosting.BackgroundService
{
    private readonly ISecureStoreClient _secureStoreClient;
    private readonly ILogger<SecureStoreBackgroundService> _logger;
    private readonly TimeSpan _healthCheckInterval = TimeSpan.FromMinutes(5);

    public SecureStoreBackgroundService(ISecureStoreClient secureStoreClient, ILogger<SecureStoreBackgroundService> logger)
    {
        _secureStoreClient = secureStoreClient;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SecureStore background service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Periodic health check
                var healthStatus = await _secureStoreClient.GetHealthStatusAsync(stoppingToken);
                if (healthStatus != null)
                {
                    if (healthStatus.IsHealthy)
                    {
                        _logger.LogDebug("SecureStore health check passed");
                    }
                    else
                    {
                        _logger.LogWarning("SecureStore health check failed: {Status}", healthStatus.Status);
                    }
                }

                await Task.Delay(_healthCheckInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in SecureStore background service");
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
        }

        _logger.LogInformation("SecureStore background service stopped");
    }
}
