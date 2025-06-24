using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;
using Coyote.Infra.Security.Tests.TestHelpers;

namespace Coyote.Infra.Security.Tests.TestHelpers
{
    /// <summary>
    /// Simple wrapper to convert Microsoft ILogger to IAuthLogger for testing
    /// </summary>
    public class TestAuthLogger : IAuthLogger
    {
        private readonly ILogger _logger;

        public TestAuthLogger(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public void LogDebug(string message) => _logger.LogDebug(message);
        public void LogInfo(string message) => _logger.LogInformation(message);
        public void LogWarning(string message) => _logger.LogWarning(message);
        public void LogError(string message) => _logger.LogError(message);
        public void LogError(string message, Exception exception) => _logger.LogError(exception, message);
    }

    /// <summary>
    /// Base class for AuthClient tests that provides dependency injection setup
    /// </summary>
    public abstract class AuthTestBase : IDisposable
    {
        protected ServiceProvider ServiceProvider { get; private set; } = null!;
        protected MockOAuth2HttpClient MockHttpClient { get; private set; } = null!;
        protected AuthClientConfig Config { get; private set; } = null!;
        private bool _disposed;

        protected AuthTestBase()
        {
            SetupServices();
        }

        protected virtual AuthClientConfig CreateDefaultConfig()
        {
            return new AuthClientConfig
            {
                ServerUrl = "https://test-auth.example.com",
                ClientId = "test-client-id",
                ClientSecret = "test-client-secret",
                DefaultScopes = new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = false
            };
        }

        protected virtual void ConfigureServices(IServiceCollection services)
        {
            // Override this method in derived classes to customize service registration
        }

        private void SetupServices()
        {
            // Create test configuration
            Config = CreateDefaultConfig();

            // Setup dependency injection
            var services = new ServiceCollection();

            // Add logging
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));

            // Register HTTP client infrastructure
            MockHttpClient = new MockOAuth2HttpClient();
            services.AddSingleton<ICoyoteHttpClient>(MockHttpClient);
            services.AddSingleton<MockOAuth2HttpClient>(MockHttpClient);            // Register auth configuration and services
            services.AddSingleton(Config);
            services.AddSingleton(provider => Config.ToAuthClientOptions());
            services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
            services.AddTransient<IAuthLogger, ConsoleAuthLogger>();            // Register the concrete AuthClient class for DI - use the real implementation
            services.AddTransient<AuthClient>(provider => 
            {
                var config = provider.GetRequiredService<AuthClientConfig>();
                var msLogger = provider.GetRequiredService<ILogger<AuthClient>>();
                var httpClient = provider.GetRequiredService<ICoyoteHttpClient>();
                var tokenStorage = provider.GetRequiredService<IAuthTokenStorage>();                return new AuthClient(config, httpClient, tokenStorage, new TestAuthLogger(msLogger));
            });

            // Register SecureStoreClient for tests that need it
            services.AddTransient<SecureStoreClient>(provider =>
            {
                var config = provider.GetRequiredService<AuthClientConfig>();
                var msLogger = provider.GetRequiredService<ILogger<AuthClient>>();
                var httpClient = provider.GetRequiredService<ICoyoteHttpClient>();
                var tokenStorage = provider.GetRequiredService<IAuthTokenStorage>();
                var authClient = new AuthClient(config, httpClient, tokenStorage, new TestAuthLogger(msLogger));
                
                var secureStoreOptions = new SecureStoreOptions
                {
                    ServerUrl = "https://test-keyvault.coyotesense.io",
                    ApiVersion = "v1",
                    TimeoutMs = 30000,
                    VerifySsl = false
                };
                var logger = provider.GetRequiredService<ILogger<SecureStoreClient>>();
                return new SecureStoreClient(secureStoreOptions, authClient, logger);
            });

            // Allow derived classes to customize services
            ConfigureServices(services);

            ServiceProvider = services.BuildServiceProvider();
        }        protected AuthClient CreateAuthClient(AuthClientConfig? customConfig = null)
        {
            var config = customConfig ?? Config;
            var msLogger = ServiceProvider.GetRequiredService<ILogger<AuthClient>>();
            var httpClient = ServiceProvider.GetRequiredService<ICoyoteHttpClient>();
            var tokenStorage = ServiceProvider.GetRequiredService<IAuthTokenStorage>();

            // Use the mock AuthClient constructor: AuthClient(config, httpClient, tokenStorage, authLogger)
            return new AuthClient(config, httpClient, tokenStorage, new TestAuthLogger(msLogger));
        }        protected AuthClient CreateAuthClientWithNullableConfig(AuthClientConfig? config)
        {
            var msLogger = ServiceProvider.GetRequiredService<ILogger<AuthClient>>();
            var httpClient = ServiceProvider.GetRequiredService<ICoyoteHttpClient>();
            var tokenStorage = ServiceProvider.GetRequiredService<IAuthTokenStorage>();

            // Use the mock AuthClient constructor with correct parameter order
            return new AuthClient(config!, httpClient, tokenStorage, new TestAuthLogger(msLogger));
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    MockHttpClient?.Dispose();
                    ServiceProvider?.Dispose();
                }
                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
