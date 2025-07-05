using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Tests.TestHelpers;
using Coyote.Infra.Http;

namespace Coyote.OAuth2.Client.Tests.Integration
{
    /// <summary>
    /// Integration tests for OAuth2 client using only open source components
    /// Uses MockOAuth2HttpClient instead of WireMock
    /// </summary>
    public class OpenSourceOAuth2IntegrationTests : IDisposable
    {
        private readonly MockOAuth2HttpClient _mockHttpClient;
        private readonly AuthClient _authClient;
        private readonly IServiceProvider _serviceProvider;
        private readonly ITestOutputHelper _output;
        
        public OpenSourceOAuth2IntegrationTests(ITestOutputHelper output)
        {
            _output = output;
            
            // Setup DI container with MockOAuth2HttpClient (no WireMock)
            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
            
            // Register our custom OAuth2 mock HTTP client (no WireMock dependency)
            _mockHttpClient = new MockOAuth2HttpClient();
            services.AddSingleton<ICoyoteHttpClient>(_mockHttpClient);
            services.AddSingleton<MockOAuth2HttpClient>(_mockHttpClient);
            services.AddSingleton<Coyote.Infra.Http.Factory.IHttpClientFactory>(provider => 
            {
                var httpClient = provider.GetRequiredService<ICoyoteHttpClient>();
                return new TestHttpClientFactory(httpClient, RuntimeMode.Testing);
            });
            
            // Register auth infrastructure
            services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
            services.AddTransient<IAuthLogger>(provider => 
            {
                var logger = provider.GetRequiredService<ILogger<TestAuthLogger>>();
                return new TestAuthLogger(logger);
            });
            
            _serviceProvider = services.BuildServiceProvider();
            
            // Create auth client configuration using mock server endpoints
            var config = new AuthClientConfig
            {
                AuthMode = AuthMode.ClientCredentials,
                ServerUrl = "https://mock-oauth2-server.test", // Mock server URL
                ClientId = "test-client",
                ClientSecret = "test-secret",
                DefaultScopes = new List<string> { "api.read", "api.write" },
                TimeoutMs = 5000 // 5 second timeout for OAuth operations
            };
            
            _authClient = new AuthClient(config, _mockHttpClient, 
                _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
                _serviceProvider.GetRequiredService<IAuthLogger>());
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task ClientCredentialsFlow_WithOpenSourceMock_ShouldAuthenticateSuccessfully()
        {
            // Act
            var authResult = await _authClient.AuthenticateClientCredentialsAsync();

            // Assert
            authResult.Should().NotBeNull();
            authResult.IsSuccess.Should().BeTrue();
            authResult.Token.Should().NotBeNull();
            authResult.Token!.AccessToken.Should().NotBeNullOrEmpty();
            authResult.Token.TokenType.Should().Be("Bearer");

            _output.WriteLine($"Successfully authenticated with token: {authResult.Token.AccessToken[..10]}...");
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task TokenIntrospection_WithValidToken_ShouldReturnActive()
        {
            // Arrange - First get a valid token
            var authResult = await _authClient.AuthenticateClientCredentialsAsync();
            authResult.IsSuccess.Should().BeTrue();
            
            _output.WriteLine($"[DEBUG] Generated token: {authResult.Token!.AccessToken}");
            _output.WriteLine($"[DEBUG] Token length: {authResult.Token!.AccessToken.Length}");
            _output.WriteLine($"[DEBUG] Token starts with: {authResult.Token!.AccessToken.Substring(0, Math.Min(20, authResult.Token!.AccessToken.Length))}");
            
            // Act
            var introspectionResult = await _authClient.IntrospectTokenAsync(authResult.Token!.AccessToken);

            // Assert
            introspectionResult.Should().BeTrue("the generated token should be recognized as valid during introspection");
            _output.WriteLine($"Token introspection successful for token: {authResult.Token.AccessToken[..10]}...");
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task AuthorizationCodeFlow_WithValidCode_ShouldReturnTokens()
        {
            // Arrange
            const string authCode = "test-auth-code";
            const string redirectUri = "https://test-app.example.com/callback";

            // Act
            var authResult = await _authClient.AuthenticateAuthorizationCodeAsync(authCode, redirectUri);

            // Assert
            authResult.Should().NotBeNull();
            authResult.IsSuccess.Should().BeTrue();
            authResult.Token.Should().NotBeNull();
            authResult.Token!.AccessToken.Should().NotBeNullOrEmpty();
            authResult.Token.TokenType.Should().Be("Bearer");
            authResult.Token.RefreshToken.Should().NotBeNullOrEmpty("Authorization code flow should return a refresh token");

            _output.WriteLine($"Authorization code flow successful with access token: {authResult.Token.AccessToken[..10]}...");
            _output.WriteLine($"Refresh token: {authResult.Token.RefreshToken![..10]}...");
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task RefreshTokenFlow_WithValidRefreshToken_ShouldReturnNewTokens()
        {
            // Arrange - First get tokens via authorization code flow
            const string authCode = "test-auth-code";
            const string redirectUri = "https://test-app.example.com/callback";
            
            var initialAuthResult = await _authClient.AuthenticateAuthorizationCodeAsync(authCode, redirectUri);
            initialAuthResult.IsSuccess.Should().BeTrue();
            initialAuthResult.Token!.RefreshToken.Should().NotBeNullOrEmpty();

            // Act
            var refreshResult = await _authClient.RefreshTokenAsync(initialAuthResult.Token.RefreshToken!);

            // Assert
            refreshResult.Should().NotBeNull();
            refreshResult.IsSuccess.Should().BeTrue();
            refreshResult.Token.Should().NotBeNull();
            refreshResult.Token!.AccessToken.Should().NotBeNullOrEmpty();
            refreshResult.Token.TokenType.Should().Be("Bearer");
            refreshResult.Token.RefreshToken.Should().NotBeNullOrEmpty("Refresh should provide a new refresh token");

            _output.WriteLine($"Token refresh successful with new access token: {refreshResult.Token.AccessToken[..10]}...");
            _output.WriteLine($"New refresh token: {refreshResult.Token.RefreshToken![..10]}...");
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task DiscoveryEndpoint_ShouldReturnValidConfiguration()
        {
            // Act
            var serverInfo = await _authClient.GetServerInfoAsync();

            // Assert
            serverInfo.Should().NotBeNull();
            serverInfo!.TokenEndpoint.Should().NotBeNullOrEmpty();
            serverInfo.AuthorizationEndpoint.Should().NotBeNullOrEmpty();

            _output.WriteLine($"Discovery successful - Token endpoint: {serverInfo.TokenEndpoint}");
            _output.WriteLine($"Authorization endpoint: {serverInfo.AuthorizationEndpoint}");
        }

        public void Dispose()
        {
            _mockHttpClient?.Dispose();
            if (_serviceProvider is IDisposable disposableServiceProvider)
            {
                disposableServiceProvider.Dispose();
            }
        }
    }
}
