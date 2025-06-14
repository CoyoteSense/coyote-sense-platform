using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Coyote.Infra.Http;
using Coyote.Infra.Security.Auth.Options;

namespace Coyote.Infra.Security.Auth.Extensions;

/// <summary>
/// Dependency injection extensions for authentication clients
/// Provides clean integration with .NET's built-in DI container
/// </summary>
public static class AuthClientServiceCollectionExtensions
{
    /// <summary>
    /// Add authentication client with Client Credentials flow to DI container
    /// </summary>
    public static IServiceCollection AddAuthClientWithClientCredentials(
        this IServiceCollection services,
        Action<ClientCredentialsOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddScoped<IAuthClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<ClientCredentialsOptions>>();
            var logger = provider.GetService<IAuthLogger>();
            var tokenStorage = provider.GetService<IAuthTokenStorage>();
            var httpClient = provider.GetService<ICoyoteHttpClient>();

            return AuthClientFactory.CreateFromOptions(options.Value, tokenStorage, logger, httpClient);
        });

        return services;
    }

    /// <summary>
    /// Add authentication client with mTLS flow to DI container
    /// </summary>
    public static IServiceCollection AddAuthClientWithMtls(
        this IServiceCollection services,
        Action<MtlsOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddScoped<IAuthClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<MtlsOptions>>();
            var logger = provider.GetService<IAuthLogger>();
            var tokenStorage = provider.GetService<IAuthTokenStorage>();
            var httpClient = provider.GetService<ICoyoteHttpClient>();

            return AuthClientFactory.CreateFromOptions(options.Value, tokenStorage, logger, httpClient);
        });

        return services;
    }

    /// <summary>
    /// Add authentication client with JWT Bearer flow to DI container
    /// </summary>
    public static IServiceCollection AddAuthClientWithJwtBearer(
        this IServiceCollection services,
        Action<JwtBearerOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddScoped<IAuthClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<JwtBearerOptions>>();
            var logger = provider.GetService<IAuthLogger>();
            var tokenStorage = provider.GetService<IAuthTokenStorage>();
            var httpClient = provider.GetService<ICoyoteHttpClient>();

            return AuthClientFactory.CreateFromOptions(options.Value, tokenStorage, logger, httpClient);
        });

        return services;
    }

    /// <summary>
    /// Add authentication client with Authorization Code flow to DI container
    /// </summary>
    public static IServiceCollection AddAuthClientWithAuthorizationCode(
        this IServiceCollection services,
        Action<AuthorizationCodeOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddScoped<IAuthClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<AuthorizationCodeOptions>>();
            var logger = provider.GetService<IAuthLogger>();
            var tokenStorage = provider.GetService<IAuthTokenStorage>();
            var httpClient = provider.GetService<ICoyoteHttpClient>();

            return AuthClientFactory.CreateFromOptions(options.Value, tokenStorage, logger, httpClient);
        });

        return services;
    }

    /// <summary>
    /// Add default authentication services
    /// </summary>
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services)
    {
        services.AddSingleton<IAuthTokenStorage, InMemoryTokenStorage>();
        services.AddSingleton<IAuthLogger, MicrosoftLoggingAdapter>();
        services.AddScoped<AuthClientPool>();

        return services;
    }
}

/// <summary>
/// Pool for managing multiple authentication clients
/// Useful for scenarios where you need different auth flows in the same application
/// </summary>
public class AuthClientPool : IDisposable
{
    private readonly ConcurrentDictionary<string, IAuthClient> _clients = new();
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AuthClientPool> _logger;
    private bool _disposed;

    public AuthClientPool(IServiceProvider serviceProvider, ILogger<AuthClientPool> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    /// <summary>
    /// Get or create a client credentials client
    /// </summary>
    public IAuthClient GetClientCredentialsClient(string name, ClientCredentialsOptions options)
    {
        return _clients.GetOrAdd($"client-creds-{name}", _ =>
        {
            _logger.LogInformation("Creating Client Credentials client: {Name}", name);
            return AuthClientFactory.CreateFromOptions(options);
        });
    }

    /// <summary>
    /// Get or create an mTLS client
    /// </summary>
    public IAuthClient GetMtlsClient(string name, MtlsOptions options)
    {
        return _clients.GetOrAdd($"mtls-{name}", _ =>
        {
            _logger.LogInformation("Creating mTLS client: {Name}", name);
            return AuthClientFactory.CreateFromOptions(options);
        });
    }

    /// <summary>
    /// Get or create a JWT Bearer client
    /// </summary>
    public IAuthClient GetJwtBearerClient(string name, JwtBearerOptions options)
    {
        return _clients.GetOrAdd($"jwt-{name}", _ =>
        {
            _logger.LogInformation("Creating JWT Bearer client: {Name}", name);
            return AuthClientFactory.CreateFromOptions(options);
        });
    }

    /// <summary>
    /// Remove a client from the pool
    /// </summary>
    public bool RemoveClient(string name, string type)
    {
        var key = $"{type}-{name}";
        if (_clients.TryRemove(key, out var client))
        {
            _logger.LogInformation("Removing client from pool: {Key}", key);
            client.Dispose();
            return true;
        }
        return false;
    }

    /// <summary>
    /// Get client statistics
    /// </summary>
    public int ActiveClientCount => _clients.Count;

    public void Dispose()
    {
        if (!_disposed)
        {
            foreach (var client in _clients.Values)
            {
                client.Dispose();
            }
            _clients.Clear();
            _disposed = true;
        }
    }
}

/// <summary>
/// Adapter to bridge IAuthLogger with Microsoft.Extensions.Logging
/// </summary>
public class MicrosoftLoggingAdapter : IAuthLogger
{
    private readonly ILogger<MicrosoftLoggingAdapter> _logger;

    public MicrosoftLoggingAdapter(ILogger<MicrosoftLoggingAdapter> logger)
    {
        _logger = logger;
    }

    public void LogInfo(string message) => _logger.LogInformation(message);
    public void LogWarning(string message) => _logger.LogWarning(message);
    public void LogError(string message) => _logger.LogError(message);
    public void LogDebug(string message) => _logger.LogDebug(message);
}

/// <summary>
/// Background service for managing authentication client health
/// </summary>
public class AuthClientHealthService : BackgroundService
{
    private readonly AuthClientPool _clientPool;
    private readonly ILogger<AuthClientHealthService> _logger;
    private readonly TimeSpan _checkInterval;

    public AuthClientHealthService(
        AuthClientPool clientPool,
        ILogger<AuthClientHealthService> logger,
        IConfiguration configuration)
    {
        _clientPool = clientPool;
        _logger = logger;
        _checkInterval = TimeSpan.FromMinutes(
            configuration.GetValue<int>("AuthClient:HealthCheckIntervalMinutes", 5));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Auth Client Health Service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PerformHealthChecks(stoppingToken);
                await Task.Delay(_checkInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during auth client health check");
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }

        _logger.LogInformation("Auth Client Health Service stopped");
    }

    private async Task PerformHealthChecks(CancellationToken cancellationToken)
    {
        var activeClients = _clientPool.ActiveClientCount;
        _logger.LogDebug("Performing health check for {ActiveClients} auth clients", activeClients);

        // Add specific health check logic here
        // For example, testing token validity, connection health, etc.

        await Task.CompletedTask;
    }
}
