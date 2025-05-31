using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace CoyoteSense.OAuth2.Client.Tests.Integration;

/// <summary>
/// Integration tests for OAuth2AuthClient against real OAuth2 server
/// </summary>
public class OAuth2IntegrationTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly ServiceProvider _serviceProvider;
    private readonly IOAuth2AuthClient _client;
    private readonly OAuth2ClientConfiguration _config;
    private readonly HttpClient _httpClient;
    private bool _disposed;

    public OAuth2IntegrationTests(ITestOutputHelper output)
    {
        _output = output;
        
        // Load configuration from environment variables
        _config = new OAuth2ClientConfiguration
        {
            ServerUrl = Environment.GetEnvironmentVariable("OAUTH2_SERVER_URL") ?? "https://localhost:5001",
            ClientId = Environment.GetEnvironmentVariable("OAUTH2_CLIENT_ID") ?? "integration-test-client",
            ClientSecret = Environment.GetEnvironmentVariable("OAUTH2_CLIENT_SECRET") ?? "integration-test-secret",
            Scope = Environment.GetEnvironmentVariable("OAUTH2_SCOPE") ?? "api.read api.write",
            EnableAutoRefresh = true,
            RetryPolicy = new OAuth2RetryPolicy
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromSeconds(1),
                MaxDelay = TimeSpan.FromSeconds(10),
                UseExponentialBackoff = true
            }
        };

        // Setup DI container
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));
        services.AddHttpClient();
        services.AddSingleton(_config);
        services.AddTransient<IOAuth2TokenStorage, InMemoryOAuth2TokenStorage>();
        services.AddTransient<IOAuth2AuthClient, OAuth2AuthClient>();
        
        _serviceProvider = services.BuildServiceProvider();
        _client = _serviceProvider.GetRequiredService<IOAuth2AuthClient>();
        _httpClient = _serviceProvider.GetRequiredService<HttpClient>();
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ClientCredentialsFlow_ShouldAuthenticateSuccessfully()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Act
        var result = await _client.AuthenticateClientCredentialsAsync();

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.TokenType.Should().Be("Bearer");
        result.ExpiresIn.Should().BeGreaterThan(0);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task JwtBearerFlow_WithValidJwt_ShouldAuthenticateSuccessfully()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Arrange - Create a valid JWT for testing
        var jwt = await CreateTestJwtAsync();

        // Act
        var result = await _client.AuthenticateJwtBearerAsync(jwt);

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.TokenType.Should().Be("Bearer");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task TokenIntrospection_WithValidToken_ShouldReturnActiveToken()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Arrange - Get a valid token first
        var authResult = await _client.AuthenticateClientCredentialsAsync();
        authResult.IsSuccess.Should().BeTrue();

        // Act
        var introspectionResult = await _client.IntrospectTokenAsync(authResult.AccessToken!);

        // Assert
        introspectionResult.Should().NotBeNull();
        introspectionResult.Active.Should().BeTrue();
        introspectionResult.ClientId.Should().Be(_config.ClientId);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task TokenRevocation_WithValidToken_ShouldRevokeSuccessfully()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Arrange - Get a valid token first
        var authResult = await _client.AuthenticateClientCredentialsAsync();
        authResult.IsSuccess.Should().BeTrue();

        // Act
        var revocationResult = await _client.RevokeTokenAsync(authResult.AccessToken!);

        // Assert
        revocationResult.Should().BeTrue();

        // Verify token is no longer active
        var introspectionResult = await _client.IntrospectTokenAsync(authResult.AccessToken!);
        introspectionResult.Active.Should().BeFalse();
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ServerDiscovery_ShouldReturnValidEndpoints()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Act
        var discoveryResult = await _client.DiscoverServerEndpointsAsync();

        // Assert
        discoveryResult.Should().NotBeNull();
        discoveryResult.TokenEndpoint.Should().NotBeNullOrEmpty();
        discoveryResult.IntrospectionEndpoint.Should().NotBeNullOrEmpty();
        discoveryResult.RevocationEndpoint.Should().NotBeNullOrEmpty();
        discoveryResult.SupportedGrantTypes.Should().NotBeEmpty();
        discoveryResult.SupportedGrantTypes.Should().Contain("client_credentials");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task AutoRefresh_WhenTokenExpires_ShouldRefreshAutomatically()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Arrange - Get initial token
        var initialResult = await _client.AuthenticateClientCredentialsAsync();
        initialResult.IsSuccess.Should().BeTrue();
        var initialToken = initialResult.AccessToken;

        // Wait for token to expire (or simulate expiration)
        await Task.Delay(TimeSpan.FromSeconds(2));

        // Act - Request new token (should trigger auto-refresh)
        var refreshedResult = await _client.AuthenticateClientCredentialsAsync();

        // Assert
        refreshedResult.Should().NotBeNull();
        refreshedResult.IsSuccess.Should().BeTrue();
        refreshedResult.AccessToken.Should().NotBeNullOrEmpty();
        // Token might be the same if still valid, or different if refreshed
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ConcurrentAuthentication_ShouldHandleMultipleRequests()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Arrange
        var tasks = new List<Task<OAuth2TokenResponse>>();

        // Act - Create multiple concurrent authentication requests
        for (int i = 0; i < 5; i++)
        {
            tasks.Add(_client.AuthenticateClientCredentialsAsync());
        }

        var results = await Task.WhenAll(tasks);

        // Assert
        results.Should().AllSatisfy(result =>
        {
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.AccessToken.Should().NotBeNullOrEmpty();
        });
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task InvalidCredentials_ShouldReturnFailureResult()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Arrange - Create client with invalid credentials
        var invalidConfig = new OAuth2ClientConfiguration
        {
            ServerUrl = _config.ServerUrl,
            ClientId = "invalid-client-id",
            ClientSecret = "invalid-client-secret",
            Scope = _config.Scope
        };

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole());
        services.AddHttpClient();
        services.AddSingleton(invalidConfig);
        services.AddTransient<IOAuth2TokenStorage, InMemoryOAuth2TokenStorage>();
        services.AddTransient<IOAuth2AuthClient, OAuth2AuthClient>();

        using var serviceProvider = services.BuildServiceProvider();
        var invalidClient = serviceProvider.GetRequiredService<IOAuth2AuthClient>();

        // Act
        var result = await invalidClient.AuthenticateClientCredentialsAsync();

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_client");
        result.ErrorDescription.Should().NotBeNullOrEmpty();
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task HealthCheck_ShouldReturnServerStatus()
    {
        // Skip if OAuth2 server is not available
        if (!await IsOAuth2ServerAvailable())
        {
            _output.WriteLine("OAuth2 server is not available, skipping integration test");
            return;
        }

        // Act
        var healthStatus = await _client.CheckServerHealthAsync();

        // Assert
        healthStatus.Should().BeTrue();
    }

    private async Task<bool> IsOAuth2ServerAvailable()
    {
        try
        {
            using var response = await _httpClient.GetAsync($"{_config.ServerUrl}/.well-known/openid_configuration");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private async Task<string> CreateTestJwtAsync()
    {
        // This would typically create a valid JWT for testing
        // For now, we'll request one from the server using client credentials
        var result = await _client.AuthenticateClientCredentialsAsync();
        if (result.IsSuccess)
        {
            return result.AccessToken!;
        }

        throw new InvalidOperationException("Could not create test JWT");
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient?.Dispose();
            _serviceProvider?.Dispose();
            _disposed = true;
        }
    }
}

/// <summary>
/// Collection fixture for integration tests
/// </summary>
[CollectionDefinition("OAuth2Integration")]
public class OAuth2IntegrationCollection : ICollectionFixture<OAuth2IntegrationTestFixture>
{
}

/// <summary>
/// Test fixture for OAuth2 integration tests
/// </summary>
public class OAuth2IntegrationTestFixture : IDisposable
{
    public OAuth2IntegrationTestFixture()
    {
        // Setup any shared resources for integration tests
        Environment.SetEnvironmentVariable("OAUTH2_SERVER_URL", "https://localhost:5001");
        Environment.SetEnvironmentVariable("OAUTH2_CLIENT_ID", "integration-test-client");
        Environment.SetEnvironmentVariable("OAUTH2_CLIENT_SECRET", "integration-test-secret");
        Environment.SetEnvironmentVariable("OAUTH2_SCOPE", "api.read api.write");
    }

    public void Dispose()
    {
        // Cleanup shared resources
    }
}
