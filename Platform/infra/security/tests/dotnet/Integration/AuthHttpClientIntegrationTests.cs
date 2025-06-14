using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using CoyoteSense.OAuth2.Client.Tests.Mocks;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Tests.TestHelpers;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Http.Modes.Mock;
using System.Linq;
using System.Text;

namespace CoyoteSense.OAuth2.Client.Tests.Integration;

/// <summary>
/// Integration tests for AuthClient with HTTP client infrastructure
/// Tests the proper integration between AuthClient and ICoyoteHttpClient
/// </summary>
public class AuthHttpClientIntegrationTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly ServiceProvider _serviceProvider;
    private readonly IAuthClient _authClient;
    private readonly ICoyoteHttpClient _httpClient;
    private bool _disposed;public AuthHttpClientIntegrationTests(ITestOutputHelper output)
    {
        _output = output;
        
        // For this test, we'll use either the real MockOAuth2Server OR the mock HTTP client
        // Let's use the mock HTTP client infrastructure for predictable testing
          // Setup DI container with HTTP client infrastructure
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));
        
        // Register HTTP client infrastructure
        services.AddSingleton<Coyote.Infra.Http.Factory.IHttpClientFactory, Coyote.Infra.Security.Tests.TestHelpers.TestHttpClientFactory>();
        services.AddTransient<ICoyoteHttpClient>(provider => 
            provider.GetRequiredService<Coyote.Infra.Http.Factory.IHttpClientFactory>().CreateClient());
        
        // Register auth infrastructure
        services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
        services.AddTransient<IAuthLogger, TestAuthLogger>();
        
        _serviceProvider = services.BuildServiceProvider();
        
        // Create HTTP client
        _httpClient = _serviceProvider.GetRequiredService<ICoyoteHttpClient>();
          // Setup auth client factory
        var httpClientFactory = _serviceProvider.GetRequiredService<Coyote.Infra.Http.Factory.IHttpClientFactory>();
        AuthClientFactory.SetHttpClientFactory(httpClientFactory);
        
        // Create auth client configuration using mock endpoints
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = "https://login.microsoftonline.com/test-tenant", // Mock endpoint
            ClientId = "test-client",
            ClientSecret = "test-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" }
        };
        
        _authClient = new AuthClient(config, _httpClient, 
            _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
            _serviceProvider.GetRequiredService<IAuthLogger>());
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ClientCredentialsFlow_WithHttpClientInfrastructure_ShouldAuthenticateSuccessfully()
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
    }    [Fact]
    [Trait("Category", "Integration")]
    public async Task AuthClientFactory_WithHttpClientFactory_ShouldCreateWorkingClient()
    {
        // Act
        var factoryClient = AuthClientFactory.CreateClientCredentialsClient(
            serverUrl: "https://login.microsoftonline.com/test-tenant",
            clientId: "factory-test-client",
            clientSecret: "factory-test-secret",
            defaultScopes: new List<string> { "api.read" });

        var result = await factoryClient.AuthenticateClientCredentialsAsync();

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().NotBeNullOrEmpty();
        
        factoryClient.Dispose();
        _output.WriteLine($"Factory-created client authenticated successfully");
    }    [Fact]
    [Trait("Category", "Integration")]
    public async Task JwtBearerFlow_WithHttpClientInfrastructure_ShouldAuthenticateSuccessfully()
    {
        // Arrange
        var jwtKeyPath = await CreateTestJwtKeyAsync();
        var jwtClient = AuthClientFactory.CreateJwtBearerClient(
            serverUrl: "https://login.microsoftonline.com/test-tenant",
            clientId: "jwt-test-client",
            jwtSigningKeyPath: jwtKeyPath,
            jwtIssuer: "jwt-test-client",
            jwtAudience: "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
            defaultScopes: new List<string> { "api.read" });

        // Act
        var result = await jwtClient.AuthenticateJwtBearerAsync();

        // Assert
        result.Should().NotBeNull();
        result.IsSuccess.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().NotBeNullOrEmpty();
        
        jwtClient.Dispose();
        _output.WriteLine($"JWT Bearer authentication successful");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task TokenRevocation_WithHttpClientInfrastructure_ShouldWorkCorrectly()
    {
        // Arrange - Get a token first
        var authResult = await _authClient.AuthenticateClientCredentialsAsync();
        authResult.IsSuccess.Should().BeTrue();
        var token = authResult.Token!.AccessToken;

        // Act
        var revocationResult = await _authClient.RevokeTokenAsync(token);

        // Assert
        revocationResult.Should().BeTrue();
        _output.WriteLine($"Token revocation successful");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task TokenIntrospection_WithHttpClientInfrastructure_ShouldWorkCorrectly()
    {
        // Arrange - Get a token first
        var authResult = await _authClient.AuthenticateClientCredentialsAsync();
        authResult.IsSuccess.Should().BeTrue();
        var token = authResult.Token!.AccessToken;

        // Act
        var introspectionResult = await _authClient.IntrospectTokenAsync(token);

        // Assert
        introspectionResult.Should().BeTrue();
        _output.WriteLine($"Token introspection successful");
    }    [Fact]
    [Trait("Category", "Integration")]
    public async Task RefreshToken_WithHttpClientInfrastructure_ShouldWorkCorrectly()
    {
        // Arrange - Use authorization code flow to get refresh token
        var codeClient = AuthClientFactory.CreateAuthorizationCodeClient(
            serverUrl: "https://login.microsoftonline.com/test-tenant",
            clientId: "refresh-test-client",
            clientSecret: "refresh-test-secret");

        // Simulate getting authorization code and exchanging for tokens
        var authResult = await codeClient.AuthenticateAuthorizationCodeAsync(
            authorizationCode: "test-auth-code",
            redirectUri: "http://localhost:3000/callback");
        
        authResult.IsSuccess.Should().BeTrue();
        var refreshToken = authResult.Token!.RefreshToken;
        refreshToken.Should().NotBeNullOrEmpty();

        // Act
        var refreshResult = await codeClient.RefreshTokenAsync(refreshToken!);

        // Assert
        refreshResult.Should().NotBeNull();
        refreshResult.IsSuccess.Should().BeTrue();
        refreshResult.Token.Should().NotBeNull();
        refreshResult.Token!.AccessToken.Should().NotBeNullOrEmpty();
        
        codeClient.Dispose();
        _output.WriteLine($"Token refresh successful");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task HttpClientModes_ShouldWorkAcrossDifferentModes()
    {
        // Test with different HTTP client modes
        var modes = new[] { RuntimeMode.Testing, RuntimeMode.Production, RuntimeMode.Debug };
          foreach (var mode in modes)
        {
            _output.WriteLine($"Testing with HTTP client mode: {mode}");
            
            var mockHttpClient = new MockOAuth2HttpClient();
            var factory = new TestHttpClientFactory(mockHttpClient, mode);
            var httpClient = factory.CreateHttpClientForMode(mode);
              var config = new AuthClientConfig
            {
                AuthMode = AuthMode.ClientCredentials,
                ServerUrl = "https://login.microsoftonline.com/test-tenant",
                ClientId = $"mode-test-client-{mode}",
                ClientSecret = "mode-test-secret",
                DefaultScopes = new List<string> { "api.read" }
            };
            
            using var modeClient = new AuthClient(config, httpClient, 
                new InMemoryTokenStorage(), new TestAuthLogger());
            
            var result = await modeClient.AuthenticateClientCredentialsAsync();
            
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Token.Should().NotBeNull();
            
            _output.WriteLine($"Mode {mode} test successful");
        }
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ConcurrentRequests_WithHttpClientInfrastructure_ShouldHandleCorrectly()
    {
        // Arrange
        const int concurrentRequests = 10;
        var tasks = new List<Task<AuthResult>>();

        // Act - Make multiple concurrent authentication requests
        for (int i = 0; i < concurrentRequests; i++)
        {
            var task = _authClient.AuthenticateClientCredentialsAsync();
            tasks.Add(task);
        }

        var results = await Task.WhenAll(tasks);

        // Assert
        results.Should().HaveCount(concurrentRequests);
        results.Should().OnlyContain(r => r.IsSuccess);
        results.Should().OnlyContain(r => r.Token != null);
        results.Should().OnlyContain(r => !string.IsNullOrEmpty(r.Token!.AccessToken));
        
        _output.WriteLine($"All {concurrentRequests} concurrent requests succeeded");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task Should_Use_Mock_Http_Client_Mode()
    {
        // This test verifies that we're using the mock HTTP client infrastructure
        // instead of making real HTTP calls
          // Arrange
        var factory = _serviceProvider.GetRequiredService<Coyote.Infra.Http.Factory.IHttpClientFactory>();
          // Act - Create a client in mock mode
        var mockClient = factory.CreateHttpClientForMode(RuntimeMode.Testing);
          // Make a request to our predefined mock endpoint
        var request = new HttpRequest
        {
            Method = Coyote.Infra.Http.HttpMethod.Post,
            Url = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
            Body = "grant_type=client_credentials&client_id=test&client_secret=secret"
        };
        
        // Add headers directly to the dictionary
        request.Headers["Content-Type"] = "application/x-www-form-urlencoded";
        
        var response = await mockClient.ExecuteAsync(request);
        
        // Assert - Mock client should return our predefined response
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.Body.Should().NotBeNullOrEmpty();
        response.Body.Should().Contain("mock_access_token");
        response.Body.Should().Contain("Bearer");
        response.Headers.Should().ContainKey("Content-Type");
        response.Headers["Content-Type"].Should().Contain("application/json");
          // Test discovery endpoint too
        var discoveryRequest = new HttpRequest
        {
            Method = Coyote.Infra.Http.HttpMethod.Get,
            Url = "https://login.microsoftonline.com/test-tenant/v2.0/.well-known/openid_configuration"
        };
        
        var discoveryResponse = await mockClient.ExecuteAsync(discoveryRequest);
        discoveryResponse.StatusCode.Should().Be(200);
        discoveryResponse.Body.Should().Contain("token_endpoint");
        
        _output.WriteLine("Successfully verified mock HTTP client infrastructure is working");
        _output.WriteLine($"Token response: {response.Body}");
        _output.WriteLine($"Discovery response: {discoveryResponse.Body}");
        
        mockClient.Dispose();
    }

    private async Task<string> CreateTestJwtKeyAsync()
    {
        // Create a temporary RSA key for JWT signing
        var keyPath = Path.GetTempFileName();
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var privateKey = rsa.ExportRSAPrivateKeyPem();
        await File.WriteAllTextAsync(keyPath, privateKey);
        return keyPath;
    }

    public void Dispose()
    {        if (!_disposed)
        {
            _authClient?.Dispose();
            _httpClient?.Dispose();
            _serviceProvider?.Dispose();
            _disposed = true;
        }
    }
}
