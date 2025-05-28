using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Http.Modes.Real;
using Coyote.Infra.Http.Modes.Mock;
using Coyote.Infra.Http.Modes.Record;
using Coyote.Infra.Http.Modes.Replay;
using Coyote.Infra.Http.Modes.Simulation;
using Coyote.Infra.Http.Modes.Debug;

namespace Coyote.Infra.Http.Factory;

/// <summary>
/// Factory for creating HTTP clients based on runtime mode
/// </summary>
public interface IHttpClientFactory
{
    /// <summary>
    /// Create HTTP client for current runtime mode
    /// </summary>
    ICoyoteHttpClient CreateHttpClient();
    
    /// <summary>
    /// Create HTTP client for specific runtime mode
    /// </summary>
    ICoyoteHttpClient CreateHttpClientForMode(RuntimeMode mode);
    
    /// <summary>
    /// Get current runtime mode from configuration
    /// </summary>
    RuntimeMode GetCurrentMode();
}

/// <summary>
/// Default implementation of HTTP client factory
/// </summary>
public class HttpClientFactory : IHttpClientFactory
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptions<HttpClientModeOptions> _modeOptions;
    private readonly IOptions<HttpClientOptions> _httpOptions;
    private readonly ILogger<HttpClientFactory> _logger;

    public HttpClientFactory(
        IServiceProvider serviceProvider,
        IOptions<HttpClientModeOptions> modeOptions,
        IOptions<HttpClientOptions> httpOptions,
        ILogger<HttpClientFactory> logger)
    {
        _serviceProvider = serviceProvider;
        _modeOptions = modeOptions;
        _httpOptions = httpOptions;
        _logger = logger;
    }

    public ICoyoteHttpClient CreateHttpClient()
    {
        return CreateHttpClientForMode(GetCurrentMode());
    }

    public ICoyoteHttpClient CreateHttpClientForMode(RuntimeMode mode)
    {
        _logger.LogDebug("Creating HTTP client for mode: {Mode}", mode);
        
        return mode switch
        {
            RuntimeMode.Testing => _serviceProvider.GetRequiredService<MockHttpClient>(),
            RuntimeMode.Production => _serviceProvider.GetRequiredService<RealHttpClient>(),
            RuntimeMode.Recording => _serviceProvider.GetRequiredService<RecordingHttpClient>(),
            RuntimeMode.Replay => _serviceProvider.GetRequiredService<ReplayHttpClient>(),
            RuntimeMode.Simulation => _serviceProvider.GetRequiredService<SimulationHttpClient>(),
            RuntimeMode.Debug => _serviceProvider.GetRequiredService<DebugHttpClient>(),
            _ => _serviceProvider.GetRequiredService<RealHttpClient>()
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
}

/// <summary>
/// Extension methods for dependency injection registration
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Register HTTP client infrastructure with DI container
    /// </summary>
    public static IServiceCollection AddCoyoteHttpClient(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Register configuration options
        services.Configure<HttpClientOptions>(
            configuration.GetSection("Coyote:Http"));
        services.Configure<HttpClientModeOptions>(
            configuration.GetSection("Coyote:Http:Mode"));

        // Register factory
        services.AddSingleton<IHttpClientFactory, HttpClientFactory>();

        // Register all mode implementations
        services.AddTransient<RealHttpClient>();
        services.AddTransient<MockHttpClient>();
        services.AddTransient<RecordingHttpClient>();
        services.AddTransient<ReplayHttpClient>();
        services.AddTransient<SimulationHttpClient>();
        services.AddTransient<DebugHttpClient>();

        // Register the main service
        services.AddTransient<ICoyoteHttpClient>(provider =>
        {
            var factory = provider.GetRequiredService<IHttpClientFactory>();
            return factory.CreateHttpClient();
        });

        return services;
    }

    /// <summary>
    /// Register HTTP client infrastructure with explicit mode configuration
    /// </summary>
    public static IServiceCollection AddCoyoteHttpClient(
        this IServiceCollection services,
        Action<HttpClientOptions>? configureHttp = null,
        Action<HttpClientModeOptions>? configureMode = null)
    {
        // Register configuration options
        if (configureHttp != null)
        {
            services.Configure(configureHttp);
        }
        
        if (configureMode != null)
        {
            services.Configure(configureMode);
        }

        // Register factory
        services.AddSingleton<IHttpClientFactory, HttpClientFactory>();

        // Register all mode implementations
        services.AddTransient<RealHttpClient>();
        services.AddTransient<MockHttpClient>();
        services.AddTransient<RecordingHttpClient>();
        services.AddTransient<ReplayHttpClient>();
        services.AddTransient<SimulationHttpClient>();
        services.AddTransient<DebugHttpClient>();

        // Register the main service
        services.AddTransient<ICoyoteHttpClient>(provider =>
        {
            var factory = provider.GetRequiredService<IHttpClientFactory>();
            return factory.CreateHttpClient();
        });

        return services;
    }
}