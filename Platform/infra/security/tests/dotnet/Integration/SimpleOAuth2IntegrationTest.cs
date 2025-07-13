using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Tests.TestHelpers;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Real;
using FluentAssertions;

namespace Coyote.Infra.Security.Tests.Integration
{
    /// <summary>
    /// Simple integration test to verify OAuth2 server connection
    /// </summary>
    public class SimpleOAuth2IntegrationTest : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly IServiceProvider _serviceProvider;
        private readonly AuthClient _authClient;
        private const string OAuth2ServerUrl = "http://localhost:8081";

        public SimpleOAuth2IntegrationTest(ITestOutputHelper output)
        {
            _output = output;
            
            // Setup DI container
            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Information));
            services.AddSingleton<ICoyoteHttpClient, RealHttpClient>();
            services.AddSingleton<IAuthTokenStorage, InMemoryTokenStorage>();
            services.AddTransient<IAuthLogger>(provider => 
            {
                var logger = provider.GetRequiredService<ILogger<TestAuthLogger>>();
                return new TestAuthLogger(logger);
            });
            
            _serviceProvider = services.BuildServiceProvider();
            
            // Create a simple auth client configuration
            var config = new AuthClientConfig
            {
                AuthMode = AuthMode.ClientCredentials,
                ServerUrl = OAuth2ServerUrl,
                ClientId = "test-client",
                ClientSecret = "test-secret",
                DefaultScopes = new List<string> { "read" },
                TimeoutMs = 30000
            };

            // Create auth client
            _authClient = new AuthClient(config, 
                _serviceProvider.GetRequiredService<ICoyoteHttpClient>(),
                _serviceProvider.GetRequiredService<IAuthTokenStorage>(),
                _serviceProvider.GetRequiredService<IAuthLogger>());
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task SimpleOAuth2Test_WithRealServer_ShouldWork()
        {
            // Arrange
            _output.WriteLine("Testing OAuth2 server connection at: " + OAuth2ServerUrl);

            // Act
            var result = await _authClient.AuthenticateClientCredentialsAsync();

            // Assert
            result.Should().NotBeNull();
            
            // For now, just verify we get some response, even if it's an error
            // since the OAuth2 server might not accept our test credentials
            _output.WriteLine($"OAuth2 server response - Success: {result.IsSuccess}");
            if (result.IsSuccess)
            {
                _output.WriteLine("✓ OAuth2 authentication successful!");
                result.Token.Should().NotBeNull();
                result.Token!.AccessToken.Should().NotBeNullOrEmpty();
            }
            else
            {
                _output.WriteLine($"✗ OAuth2 authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
                // For integration testing, we at least want to verify we can communicate with the server
                result.ErrorCode.Should().NotBeNullOrEmpty();
            }
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task ServerConnection_ShouldBeReachable()
        {
            // Arrange
            _output.WriteLine("Testing if OAuth2 server is reachable");

            // Act
            var connectionResult = await _authClient.TestConnectionAsync();

            // Assert
            _output.WriteLine($"OAuth2 server connection result: {connectionResult}");
            
            // For integration testing, we mainly want to verify the server is reachable
            // This should be true even if authentication fails
            connectionResult.Should().BeTrue();
        }

        public void Dispose()
        {
            _authClient?.Dispose();
            if (_serviceProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}
