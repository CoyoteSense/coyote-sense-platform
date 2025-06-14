using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;
using Coyote.Infra.Security.Tests.TestHelpers;

namespace Coyote.Infra.Security.Tests.Unit
{
    /// <summary>
    /// Basic unit tests for AuthClient
    /// </summary>
    public class BasicAuthClientTests : IDisposable
    {
        private readonly ServiceProvider _serviceProvider;
        private readonly IAuthClient _client;
        private readonly MockOAuth2HttpClient _mockHttpClient;
        private readonly AuthClientConfig _config;
        private bool _disposed;

        public BasicAuthClientTests()
        {
            // Create minimal configuration
            _config = new AuthClientConfig
            {
                ServerUrl = "https://test-auth.example.com",
                ClientId = "test-client-id",
                ClientSecret = "test-client-secret",
                DefaultScopes = new List<string> { "api.read", "api.write" },
                AutoRefresh = true
            };

            // Setup DI container
            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));

            // Register our custom OAuth2 mock HTTP client
            services.AddSingleton<MockOAuth2HttpClient>();
            services.AddSingleton<ICoyoteHttpClient>(provider => provider.GetRequiredService<MockOAuth2HttpClient>());
            services.AddSingleton<Coyote.Infra.Http.Factory.IHttpClientFactory>(provider =>
            {
                var httpClient = provider.GetRequiredService<ICoyoteHttpClient>();
                return new TestHttpClientFactory(httpClient);
            });

            services.AddSingleton(_config);
            services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
            services.AddTransient<IAuthClient, AuthClient>();

            _serviceProvider = services.BuildServiceProvider();
            _client = _serviceProvider.GetRequiredService<IAuthClient>();
            _mockHttpClient = _serviceProvider.GetRequiredService<MockOAuth2HttpClient>();
        }

        [Fact]
        public async Task ClientCredentialsFlow_ShouldAuthenticateSuccessfully()
        {
            // Act
            var result = await _client.AuthenticateClientCredentialsAsync();

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();

            result.Token.Should().NotBeNull();
            result.Token!.AccessToken.Should().NotBeNullOrEmpty();
            result.Token.TokenType.Should().Be("Bearer");
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _serviceProvider?.Dispose();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// In-memory token storage for testing
    /// </summary>
    public class InMemoryTokenStorage : IAuthTokenStorage
    {
        private readonly Dictionary<string, AuthToken> _tokens = new();

        public Task<AuthToken?> GetTokenAsync(string key)
        {
            _tokens.TryGetValue(key, out var token);
            return Task.FromResult(token);
        }

        public Task StoreTokenAsync(string key, AuthToken token)
        {
            _tokens[key] = token;
            return Task.CompletedTask;
        }

        public Task ClearTokenAsync(string key)
        {
            _tokens.Remove(key);
            return Task.CompletedTask;
        }

        public AuthToken? GetToken(string clientId)
        {
            _tokens.TryGetValue(clientId, out var token);
            return token;
        }

        public void ClearToken(string clientId)
        {
            _tokens.Remove(clientId);
        }

        public void ClearAllTokens()
        {
            _tokens.Clear();
        }
    }
}
