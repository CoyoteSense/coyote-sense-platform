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
            provider.GetRequiredService<Coyote.Infra.Http.Factory.IHttpClientFactory>().CreateHttpClient());
        
        // Register auth infrastructure
        services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
        services.AddTransient<IAuthLogger, TestAuthLogger>();
        
        _serviceProvider = services.BuildServiceProvider();
        
        // Create HTTP client
        _httpClient = _serviceProvider.GetRequiredService<ICoyoteHttpClient>();
        
        // Setup auth client factory
        var httpClientFactory = _serviceProvider.GetRequiredService<IHttpClientFactory>();
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
            
            var factory = new TestHttpClientFactory(mode);
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

/// <summary>
/// Test implementation of HTTP client factory for integration testing
/// </summary>
internal class TestHttpClientFactory : Coyote.Infra.Http.Factory.IHttpClientFactory
{
    private readonly RuntimeMode _defaultMode;

    public TestHttpClientFactory(RuntimeMode defaultMode = RuntimeMode.Testing)
    {
        _defaultMode = defaultMode;
    }

    public ICoyoteHttpClient CreateHttpClient()
    {
        return CreateHttpClientForMode(_defaultMode);
    }

    public ICoyoteHttpClient CreateHttpClientForMode(RuntimeMode mode)
    {
        var options = new HttpClientOptions
        {
            DefaultTimeoutMs = 30000,
            UserAgent = $"CoyoteAuth-Test/{mode}",
            VerifyPeer = false, // For testing
            FollowRedirects = true
        };

        return mode switch
        {
            RuntimeMode.Testing => new TestMockHttpClient(options),
            RuntimeMode.Debug => new TestDebugHttpClient(options),
            _ => new TestRealHttpClient(options)
        };
    }

    public RuntimeMode GetCurrentMode() => _defaultMode;
}

/// <summary>
/// Test implementations of HTTP clients for different modes
/// </summary>
internal class TestRealHttpClient : BaseHttpClient
{
    public TestRealHttpClient(HttpClientOptions options) : base(options) { }

    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        using var httpClient = new System.Net.Http.HttpClient();
        httpClient.Timeout = TimeSpan.FromMilliseconds(request.TimeoutMs ?? 30000);
        
        var httpRequestMessage = new System.Net.Http.HttpRequestMessage(
            GetHttpMethod(request.Method), request.Url);
            
        if (!string.IsNullOrEmpty(request.Body))
        {
            httpRequestMessage.Content = new StringContent(request.Body, Encoding.UTF8, 
                request.Headers.ContainsKey("Content-Type") ? request.Headers["Content-Type"] : "application/json");
        }
        
        foreach (var header in request.Headers)
        {
            if (header.Key != "Content-Type")
                httpRequestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        
        var response = await httpClient.SendAsync(httpRequestMessage, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
          return new HttpResponse
        {
            StatusCode = (int)response.StatusCode,
            Body = body,
            Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value)),
            ErrorMessage = response.IsSuccessStatusCode ? null : "HTTP request failed"
        };
    }

    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await GetAsync(url, cancellationToken: cancellationToken);
            return response.IsSuccess;
        }
        catch
        {
            return false;
        }
    }

    private static System.Net.Http.HttpMethod GetHttpMethod(Coyote.Infra.Http.HttpMethod method)
    {
        return method switch
        {
            Coyote.Infra.Http.HttpMethod.Get => System.Net.Http.HttpMethod.Get,
            Coyote.Infra.Http.HttpMethod.Post => System.Net.Http.HttpMethod.Post,
            Coyote.Infra.Http.HttpMethod.Put => System.Net.Http.HttpMethod.Put,
            Coyote.Infra.Http.HttpMethod.Delete => System.Net.Http.HttpMethod.Delete,
            Coyote.Infra.Http.HttpMethod.Patch => System.Net.Http.HttpMethod.Patch,
            Coyote.Infra.Http.HttpMethod.Head => System.Net.Http.HttpMethod.Head,
            Coyote.Infra.Http.HttpMethod.Options => System.Net.Http.HttpMethod.Options,
            _ => System.Net.Http.HttpMethod.Get
        };
    }
}

internal class TestMockHttpClient : BaseHttpClient
{
    private readonly MockHttpClient _mockClient;
    
    public TestMockHttpClient(HttpClientOptions options) : base(options) 
    { 
        // Create mock options for OAuth2 testing
        var mockOptions = Microsoft.Extensions.Options.Options.Create(new HttpClientModeOptions
        {
            Mode = RuntimeMode.Testing,
            Mock = new MockResponseOptions
            {
                DefaultStatusCode = 200,
                DefaultBody = "{\"access_token\":\"mock_token\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                DefaultHeaders = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                DelayMs = 10
            }
        });
        
        var httpOptions = Microsoft.Extensions.Options.Options.Create(options);
        
        // Create a simple logger for testing
        var loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger<MockHttpClient>();
        
        _mockClient = new MockHttpClient(httpOptions, mockOptions, logger);
        
        // Configure common OAuth2 endpoints with appropriate mock responses
        SetupOAuth2MockResponses();
    }
    
    private void SetupOAuth2MockResponses()
    {
        // Mock token endpoint response
        _mockClient.SetPredefinedJsonResponse("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token", 
            new { access_token = "mock_access_token", token_type = "Bearer", expires_in = 3600 });
            
        // Mock discovery endpoint response
        _mockClient.SetPredefinedJsonResponse("https://login.microsoftonline.com/test-tenant/v2.0/.well-known/openid_configuration",
            new { 
                issuer = "https://login.microsoftonline.com/test-tenant/v2.0",
                token_endpoint = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
                jwks_uri = "https://login.microsoftonline.com/test-tenant/discovery/v2.0/keys"
            });
    }
    
    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        return await _mockClient.ExecuteAsync(request, cancellationToken);
    }
    
    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        return await _mockClient.PingAsync(url, cancellationToken);
    }
}

internal class TestDebugHttpClient : TestRealHttpClient
{
    public TestDebugHttpClient(HttpClientOptions options) : base(options) { }
    
    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        Console.WriteLine($"[DEBUG HTTP] {request.Method} {request.Url}");
        if (!string.IsNullOrEmpty(request.Body))
            Console.WriteLine($"[DEBUG HTTP] Body: {request.Body}");
        
        var response = await base.ExecuteAsync(request, cancellationToken);
        
        Console.WriteLine($"[DEBUG HTTP] Response: {response.StatusCode}");
        Console.WriteLine($"[DEBUG HTTP] Body: {response.Body}");
        
        return response;
    }
}
