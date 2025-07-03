using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;
using Xunit.Abstractions;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Tests.TestHelpers;
using Coyote.Infra.Http;

namespace Coyote.Infra.Security.Tests.Integration;

/// <summary>
/// Modern integration tests using the new factory-based architecture
/// </summary>
[Collection("IntegrationTests")]
public class ModernAuthIntegrationTests : AuthTestBase
{
    private readonly ITestOutputHelper _output;
    
    public ModernAuthIntegrationTests(ITestOutputHelper output) : base()
    {
        _output = output;
    }

    [Fact]
    [Trait("Category", "Integration")]
    public Task MockAuthClient_ShouldReturnValidToken()
    {
        // Arrange
        var mockOptions = Options.Create(new AuthClientOptions
        {
            ClientId = "integration-test-client",
            BaseUrl = "https://test.example.com"
        });

        var modeOptions = Options.Create(new AuthClientModeOptions
        {
            Mode = RuntimeMode.Testing
        });

        var logger = ServiceProvider.GetService<ILogger<AuthClientFactory>>() ??
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<AuthClientFactory>.Instance;

        var factory = new AuthClientFactory(ServiceProvider, modeOptions, mockOptions, logger);

        // Act
        var client = factory.CreateClient();
        
        // Assert
        client.Should().NotBeNull();
        client.Should().BeAssignableTo<IAuthClient>();
        
        // Testing client should report as authenticated
        client.IsAuthenticated.Should().BeTrue();
        
        _output.WriteLine($"Created client of type: {client.GetType().Name}");
        _output.WriteLine($"Client is authenticated: {client.IsAuthenticated}");
        
        return Task.CompletedTask;
    }

    [Fact]
    [Trait("Category", "Integration")]
    public Task DebugAuthClient_ShouldReturnValidToken()
    {
        // Arrange
        var debugOptions = Options.Create(new AuthClientOptions
        {
            ClientId = "debug-test-client",
            BaseUrl = "https://debug.example.com"
        });

        var modeOptions = Options.Create(new AuthClientModeOptions
        {
            Mode = RuntimeMode.Debug
        });

        var logger = ServiceProvider.GetService<ILogger<AuthClientFactory>>() ??
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<AuthClientFactory>.Instance;

        var factory = new AuthClientFactory(ServiceProvider, modeOptions, debugOptions, logger);

        // Act
        var client = factory.CreateClient();
        
        // Assert
        client.Should().NotBeNull();
        client.Should().BeAssignableTo<IAuthClient>();
        
        // Debug client should report as authenticated
        client.IsAuthenticated.Should().BeTrue();
        
        _output.WriteLine($"Created client of type: {client.GetType().Name}");
        _output.WriteLine($"Client is authenticated: {client.IsAuthenticated}");
        
        return Task.CompletedTask;
    }

    [Fact]
    [Trait("Category", "Integration")]
    public Task RealAuthClient_WithHttpClient_ShouldBeCreated()
    {
        // Arrange
        var realOptions = Options.Create(new AuthClientOptions
        {
            ClientId = "real-test-client",
            BaseUrl = "https://auth.example.com",
            ClientSecret = "test-secret"
        });

        var modeOptions = Options.Create(new AuthClientModeOptions
        {
            Mode = RuntimeMode.Production
        });

        var logger = ServiceProvider.GetService<ILogger<AuthClientFactory>>() ??
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<AuthClientFactory>.Instance;

        var factory = new AuthClientFactory(ServiceProvider, modeOptions, realOptions, logger);

        // Act
        var client = factory.CreateClient();
        
        // Assert
        client.Should().NotBeNull();
        client.Should().BeAssignableTo<IAuthClient>();
        
        // Real client should start as not authenticated until actual auth call
        client.IsAuthenticated.Should().BeFalse();
        
        _output.WriteLine($"Created client of type: {client.GetType().Name}");
        _output.WriteLine($"Client is authenticated: {client.IsAuthenticated}");
        
        return Task.CompletedTask;
    }
}
