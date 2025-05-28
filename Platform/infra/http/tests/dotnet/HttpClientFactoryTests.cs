using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Http.Modes.Mock;
using Coyote.Infra.Http.Modes.Real;
using Coyote.Infra.Http.Modes.Record;
using Coyote.Infra.Http.Modes.Replay;
using Coyote.Infra.Http.Modes.Simulation;
using Coyote.Infra.Http.Modes.Debug;
using FluentAssertions;
using Xunit;

namespace Coyote.Infra.Http.Tests;

/// <summary>
/// Unit tests for HTTP client factory
/// </summary>
public class HttpClientFactoryTests
{
    private readonly ServiceCollection _services;
    private readonly IServiceProvider _serviceProvider;

    public HttpClientFactoryTests()
    {
        _services = new ServiceCollection();
        _services.AddLogging();
        
        // Configure options
        _services.Configure<HttpClientOptions>(options => { });
        _services.Configure<HttpClientModeOptions>(options => { });
        
        // Register implementations
        _services.AddTransient<RealHttpClient>();
        _services.AddTransient<MockHttpClient>();
        _services.AddTransient<RecordingHttpClient>();
        _services.AddTransient<ReplayHttpClient>();
        _services.AddTransient<SimulationHttpClient>();
        _services.AddTransient<DebugHttpClient>();
        
        // Register factory
        _services.AddSingleton<IHttpClientFactory, HttpClientFactory>();
        
        _serviceProvider = _services.BuildServiceProvider();
    }

    [Fact]
    public void CreateHttpClientForMode_Testing_ShouldReturnMockClient()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<IHttpClientFactory>();

        // Act
        var client = factory.CreateHttpClientForMode(RuntimeMode.Testing);

        // Assert
        client.Should().NotBeNull();
        client.Should().BeOfType<MockHttpClient>();
    }

    [Fact]
    public void CreateHttpClientForMode_Production_ShouldReturnRealClient()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<IHttpClientFactory>();

        // Act
        var client = factory.CreateHttpClientForMode(RuntimeMode.Production);

        // Assert
        client.Should().NotBeNull();
        client.Should().BeOfType<RealHttpClient>();
    }

    [Theory]
    [InlineData("testing", RuntimeMode.Testing)]
    [InlineData("TESTING", RuntimeMode.Testing)]
    [InlineData("Testing", RuntimeMode.Testing)]
    [InlineData("production", RuntimeMode.Production)]
    [InlineData("PRODUCTION", RuntimeMode.Production)]
    [InlineData("Production", RuntimeMode.Production)]
    public void GetCurrentMode_WithEnvironmentVariable_ShouldReturnCorrectMode(string envValue, RuntimeMode expectedMode)
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", envValue);
        var factory = _serviceProvider.GetRequiredService<IHttpClientFactory>();

        try
        {
            // Act
            var mode = factory.GetCurrentMode();

            // Assert
            mode.Should().Be(expectedMode);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        }
    }

    [Fact]
    public void GetCurrentMode_WithModeEnvironmentVariable_ShouldReturnCorrectMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("MODE", "testing");
        var factory = _serviceProvider.GetRequiredService<IHttpClientFactory>();

        try
        {
            // Act
            var mode = factory.GetCurrentMode();

            // Assert
            mode.Should().Be(RuntimeMode.Testing);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("MODE", null);
        }
    }

    [Fact]
    public void GetCurrentMode_WithNoEnvironmentVariable_ShouldReturnConfiguredMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        Environment.SetEnvironmentVariable("MODE", null);
        
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<HttpClientOptions>(options => { });
        services.Configure<HttpClientModeOptions>(options => 
        {
            options.Mode = RuntimeMode.Debug;
        });
        
        services.AddTransient<RealHttpClient>();
        services.AddTransient<MockHttpClient>();
        services.AddTransient<RecordingHttpClient>();
        services.AddTransient<ReplayHttpClient>();
        services.AddTransient<SimulationHttpClient>();
        services.AddTransient<DebugHttpClient>();
        services.AddSingleton<IHttpClientFactory, HttpClientFactory>();
        
        var serviceProvider = services.BuildServiceProvider();
        var factory = serviceProvider.GetRequiredService<IHttpClientFactory>();

        // Act
        var mode = factory.GetCurrentMode();

        // Assert
        mode.Should().Be(RuntimeMode.Debug);
    }

    [Fact]
    public void CreateHttpClient_ShouldReturnClientBasedOnCurrentMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "testing");
        var factory = _serviceProvider.GetRequiredService<IHttpClientFactory>();

        try
        {
            // Act
            var client = factory.CreateHttpClient();

            // Assert
            client.Should().NotBeNull();
            client.Should().BeOfType<MockHttpClient>();
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        }
    }

    [Fact]
    public void GetCurrentMode_WithInvalidEnvironmentVariable_ShouldReturnConfiguredMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "invalid_mode");
        var factory = _serviceProvider.GetRequiredService<IHttpClientFactory>();

        try
        {
            // Act
            var mode = factory.GetCurrentMode();

            // Assert
            mode.Should().Be(RuntimeMode.Production); // Default from configuration
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        }
    }
}
