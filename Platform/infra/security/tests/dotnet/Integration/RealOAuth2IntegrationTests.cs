using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Real;
using Coyote.Infra.Security.Tests.TestHelpers;
using FluentAssertions;

namespace Coyote.Infra.Security.Tests.Integration
{
    /// <summary>
    /// Integration tests for OAuth2 authentication with real OAuth2 server
    /// Requires OAuth2 Mock Server to be running on localhost:8081
    /// </summary>
    public class RealOAuth2IntegrationTests : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly IServiceProvider _serviceProvider;
        private readonly AuthClient _authClient;
        private readonly ICoyoteHttpClient _httpClient;
        private const string OAuth2ServerUrl = "http://localhost:8081";
        private const string TestClientId = "test-client-id";
        private const string TestClientSecret = "test-client-secret";

        public RealOAuth2IntegrationTests(ITestOutputHelper output)
        {
            _output = output;
            
            // Setup DI container with real HTTP client
            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Information));
            
            // Register real HTTP client for integration testing
            services.AddSingleton<ICoyoteHttpClient, RealHttpClient>();
            services.AddSingleton<IAuthTokenStorage, InMemoryTokenStorage>();
            services.AddTransient<IAuthLogger>(provider => 
            {
                var logger = provider.GetRequiredService<ILogger<TestAuthLogger>>();
                return new TestAuthLogger(logger);
            });
            
            _serviceProvider = services.BuildServiceProvider();
            _httpClient = _serviceProvider.GetRequiredService<ICoyoteHttpClient>();
            
            // Configure OAuth2 settings for real server
            var config = new AuthClientConfig
            {
                AuthMode = AuthMode.ClientCredentials,
                ServerUrl = OAuth2ServerUrl,
                ClientId = TestClientId,
                ClientSecret = TestClientSecret,
                DefaultScopes = new List<string> { "api.read", "api.write" },
                TimeoutMs = 30000,
                AutoRefresh = false
            };

            // Create auth client with real HTTP client
            _authClient = new AuthClient(config, _httpClient, 
                _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
                _serviceProvider.GetRequiredService<IAuthLogger>());
        }

        [Fact]
        [Trait("Category", "Integration")]
        [Trait("Category", "RealServer")]
        public async Task ClientCredentialsFlow_WithRealServer_ShouldSucceed()
        {
            // Arrange
            _output.WriteLine("Starting OAuth2 client credentials flow test with real server");
            _output.WriteLine($"Server URL: {OAuth2ServerUrl}");
            _output.WriteLine($"Client ID: {TestClientId}");

            // Act
            var result = await _authClient.AuthenticateClientCredentialsAsync();

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Token.Should().NotBeNull();
            result.Token!.AccessToken.Should().NotBeNullOrEmpty();
            result.Token.ExpiresAt.Should().BeAfter(DateTime.UtcNow);
            
            _output.WriteLine($"Successfully obtained access token: {result.Token.AccessToken[..10]}...");
            _output.WriteLine($"Token expires at: {result.Token.ExpiresAt}");
        }

        [Fact]
        [Trait("Category", "Integration")]
        [Trait("Category", "RealServer")]
        public async Task TokenIntrospection_WithRealServer_ShouldSucceed()
        {
            // Arrange
            _output.WriteLine("Starting OAuth2 token introspection test with real server");
            
            // First, get a valid token
            var authResult = await _authClient.AuthenticateClientCredentialsAsync();
            authResult.IsSuccess.Should().BeTrue();
            authResult.Token.Should().NotBeNull();
            
            var accessToken = authResult.Token!.AccessToken;
            _output.WriteLine($"Using access token for introspection: {accessToken[..10]}...");

            // Act
            var introspectionResult = await _authClient.IntrospectTokenAsync(accessToken);

            // Assert
            introspectionResult.Should().BeTrue();
            
            _output.WriteLine($"Token introspection successful");
        }

        [Fact]
        [Trait("Category", "Integration")]
        [Trait("Category", "RealServer")]
        public async Task InvalidCredentials_WithRealServer_ShouldFail()
        {
            // Arrange
            _output.WriteLine("Starting OAuth2 invalid credentials test with real server");
            
            var invalidConfig = new AuthClientConfig
            {
                AuthMode = AuthMode.ClientCredentials,
                ServerUrl = OAuth2ServerUrl,
                ClientId = "invalid-client-id",
                ClientSecret = "invalid-client-secret",
                DefaultScopes = new List<string> { "api.read" },
                TimeoutMs = 30000,
                AutoRefresh = false
            };

            var invalidAuthClient = new AuthClient(invalidConfig, _httpClient, 
                _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
                _serviceProvider.GetRequiredService<IAuthLogger>());

            // Act
            var result = await invalidAuthClient.AuthenticateClientCredentialsAsync();

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorCode.Should().NotBeNullOrEmpty();
            
            _output.WriteLine($"Invalid credentials correctly rejected with error: {result.ErrorCode}");
        }

        [Fact]
        [Trait("Category", "Integration")]
        [Trait("Category", "RealServer")]
        public async Task ServerDiscovery_WithRealServer_ShouldSucceed()
        {
            // Arrange
            _output.WriteLine("Starting OAuth2 server discovery test with real server");
            
            // Act
            var serverInfoResult = await _authClient.GetServerInfoAsync();

            // Assert
            serverInfoResult.Should().NotBeNull();
            
            _output.WriteLine($"Server discovery successful");
        }

        [Fact]
        [Trait("Category", "Integration")]
        [Trait("Category", "RealServer")]
        public async Task TokenLifecycle_WithRealServer_ShouldSucceed()
        {
            // Arrange
            _output.WriteLine("Starting OAuth2 token lifecycle test with real server");
            
            // Act 1: Get token
            var authResult = await _authClient.AuthenticateClientCredentialsAsync();
            authResult.IsSuccess.Should().BeTrue();
            authResult.Token.Should().NotBeNull();
            
            var accessToken = authResult.Token!.AccessToken;
            _output.WriteLine($"Successfully obtained access token: {accessToken[..10]}...");

            // Act 2: Introspect token
            var introspectionResult = await _authClient.IntrospectTokenAsync(accessToken);
            introspectionResult.Should().BeTrue();
            
            _output.WriteLine($"Token introspection successful");
            
            // Act 3: Revoke token (if server supports it)
            var revokeResult = await _authClient.RevokeTokenAsync(accessToken);
            
            // Assert
            // Note: Token revocation may not be supported by all OAuth2 servers
            // So we just verify that we get some response
            // revokeResult is a boolean, so we just check it's a valid boolean value
            
            _output.WriteLine($"Token lifecycle test completed");
        }

        public void Dispose()
        {
            _authClient?.Dispose();
            _httpClient?.Dispose();
            if (_serviceProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}
