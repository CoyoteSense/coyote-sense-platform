using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using CoyoteSense.OAuth2.Client.Tests.Mocks;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Http.Modes.Real;
using Coyote.Infra.Http.Modes.Mock;
using Coyote.Infra.Http.Modes.Debug;
using Coyote.Infra.Security.Tests.TestHelpers;
using IHttpClientFactory = Coyote.Infra.Http.Factory.IHttpClientFactory;

namespace CoyoteSense.OAuth2.Client.Tests.Integration;

/// <summary>
/// Integration tests using the new MockOAuth2Server with real HTTP clients
/// Tests the full OAuth2 flow with a real WireMock server
/// </summary>
public class MockOAuth2ServerIntegrationTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly ServiceProvider _serviceProvider;
    private readonly MockOAuth2Server _mockServer;
    private readonly IAuthClient _authClient;
    private readonly ICoyoteHttpClient _httpClient;
    private bool _disposed;    public MockOAuth2ServerIntegrationTests(ITestOutputHelper output)
    {
        _output = output;
        
        // Setup real MockOAuth2Server with WireMock
        _mockServer = new MockOAuth2Server();
        
        // Setup DI container with REAL HTTP client for real server testing
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning)); // Reduce logging noise
        
        // Configure HTTP client options for real HTTP communication
        services.Configure<HttpClientOptions>(options =>
        {
            options.DefaultTimeoutMs = 5000; // 5 second timeout
            options.VerifyPeer = false; // Don't verify SSL for test server
        });
        
        // Configure HTTP client mode for Production (real HTTP client)
        services.Configure<HttpClientModeOptions>(options =>
        {
            options.Mode = RuntimeMode.Production; // Use real HTTP client
        });
        
        // Add the HTTP client factory that will create real HTTP clients
        services.AddSingleton<IHttpClientFactory, HttpClientFactory>();
        
        // Register HTTP client implementations
        services.AddTransient<RealHttpClient>();
        services.AddTransient<MockHttpClient>();
        services.AddTransient<DebugHttpClient>();
        
        // Register auth infrastructure
        services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
        services.AddTransient<IAuthLogger, TestAuthLogger>();
        
        _serviceProvider = services.BuildServiceProvider();
        
        // Create real HTTP client for real server communication
        var httpClientFactory = _serviceProvider.GetRequiredService<IHttpClientFactory>();
        _httpClient = httpClientFactory.CreateHttpClientForMode(RuntimeMode.Production);
        
        // Create auth client configuration using the real mock server
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = _mockServer.BaseUrl,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" },
            TimeoutMs = 5000 // 5 second timeout for OAuth operations
        };
        
        _authClient = new AuthClient(config, _httpClient, 
            _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
            _serviceProvider.GetRequiredService<IAuthLogger>());
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ClientCredentialsFlow_WithRealMockServer_ShouldAuthenticateSuccessfully()
    {
        // Act
        var result = await _authClient.AuthenticateClientCredentialsAsync();

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().NotBeNullOrEmpty();
        result.Token.TokenType.Should().Be("Bearer");
        result.Token.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
        
        _output.WriteLine($"Successfully authenticated with token: {result.Token.AccessToken[..10]}...");
        _output.WriteLine($"Mock server URL: {_mockServer.BaseUrl}");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task TokenIntrospection_WithValidToken_ShouldReturnActive()
    {
        // Arrange
        var authResult = await _authClient.AuthenticateClientCredentialsAsync();
        authResult.Should().NotBeNull();
        authResult.IsSuccess.Should().BeTrue();
        
        // Act
        var introspectionResult = await _authClient.IntrospectTokenAsync(authResult.Token!.AccessToken);

        // Assert
        introspectionResult.Should().BeTrue();
        _output.WriteLine($"Token introspection successful for token: {authResult.Token.AccessToken[..10]}...");
    }    [Fact]
    [Trait("Category", "Integration")]    public async Task JwtBearerFlow_WithRealMockServer_ShouldAuthenticateSuccessfully()
    {
        // Arrange
        var jwtKeyPath = await _mockServer.ExportRSAPrivateKeyAsync();
        var jwtClient = TestAuthClientFactory.CreateJwtBearerClient(
            serverUrl: _mockServer.BaseUrl,
            clientId: "test-client",
            jwtSigningKeyPath: jwtKeyPath,
            jwtIssuer: "test-client",
            jwtAudience: _mockServer.BaseUrl + "/token",
            defaultScopes: new List<string> { "api.read" });

        // Act
        var result = await jwtClient.AuthenticateJwtBearerAsync();

        // Assert
        result.Should().NotBeNull();
        
        // Debug: Output error details if authentication failed
        if (!result.IsSuccess)
        {
            _output.WriteLine($"JWT Bearer authentication failed!");
            _output.WriteLine($"Error Code: {result.ErrorCode}");
            _output.WriteLine($"Error Description: {result.ErrorDescription}");
            _output.WriteLine($"Error Details: {result.ErrorDetails}");
        }
        
        result.IsSuccess.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().NotBeNullOrEmpty();
        
        jwtClient.Dispose();
        _output.WriteLine($"JWT Bearer authentication successful");
    }[Fact]
    [Trait("Category", "Integration")]
    public async Task DiscoveryEndpoint_ShouldReturnValidConfiguration()
    {
        // Act
        var discoveryUrl = $"{_mockServer.BaseUrl}/.well-known/openid_configuration";
        var request = new HttpRequest
        {
            Method = Coyote.Infra.Http.HttpMethod.Get,
            Url = discoveryUrl
        };
        
        var response = await _httpClient.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.Body.Should().NotBeNullOrEmpty();
        response.Body.Should().Contain("token_endpoint");
        response.Body.Should().Contain("jwks_uri");
        
        _output.WriteLine($"Discovery endpoint response: {response.Body}");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task AuthorizationCodeFlow_WithValidCode_ShouldReturnTokens()
    {
        // Arrange - Use the integration test client that supports authorization code flow
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.AuthorizationCode,
            ServerUrl = _mockServer.BaseUrl,
            ClientId = "integration-test-client",
            ClientSecret = "integration-test-secret",
            RedirectUri = "http://localhost:8080/callback"
        };
        
        var authCodeClient = new AuthClient(config, _httpClient,
            _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
            _serviceProvider.GetRequiredService<IAuthLogger>());

        // Act - Use test authorization code
        var result = await authCodeClient.AuthenticateAuthorizationCodeAsync("test-auth-code", "https://localhost:3000/callback");

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().NotBeNullOrEmpty();
        result.Token.RefreshToken.Should().NotBeNullOrEmpty();
        
        authCodeClient.Dispose();
        _output.WriteLine($"Authorization code flow successful");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task RefreshTokenFlow_WithValidRefreshToken_ShouldReturnNewTokens()
    {
        // Arrange - First get tokens via authorization code flow
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.AuthorizationCode,
            ServerUrl = _mockServer.BaseUrl,
            ClientId = "integration-test-client",
            ClientSecret = "integration-test-secret",
            RedirectUri = "http://localhost:8080/callback"
        };
        
        var authCodeClient = new AuthClient(config, _httpClient,
            _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
            _serviceProvider.GetRequiredService<IAuthLogger>());

        var initialResult = await authCodeClient.AuthenticateAuthorizationCodeAsync("test-auth-code", "https://localhost:3000/callback");
        initialResult.IsSuccess.Should().BeTrue();
        var refreshToken = initialResult.Token!.RefreshToken;

        // Act - Use refresh token to get new access token
        var refreshResult = await authCodeClient.RefreshTokenAsync(refreshToken!);

        // Assert
        refreshResult.Should().NotBeNull();
        refreshResult.IsSuccess.Should().BeTrue();
        refreshResult.Token.Should().NotBeNull();
        refreshResult.Token!.AccessToken.Should().NotBeNullOrEmpty();
        refreshResult.Token.AccessToken.Should().NotBe(initialResult.Token.AccessToken);
        
        authCodeClient.Dispose();
        _output.WriteLine($"Refresh token flow successful");
    }

    private async Task<string> CreateTestJwtKeyAsync()
    {
        var keyPath = Path.Combine(Path.GetTempPath(), $"test-jwt-key-{Guid.NewGuid()}.pem");
        
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var privateKey = rsa.ExportRSAPrivateKeyPem();
        await File.WriteAllTextAsync(keyPath, privateKey);
        
        return keyPath;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _authClient?.Dispose();
            _httpClient?.Dispose();
            _mockServer?.Dispose();
            _serviceProvider?.Dispose();
            _disposed = true;
        }
    }
}
