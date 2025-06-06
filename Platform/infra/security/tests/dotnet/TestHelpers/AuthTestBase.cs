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
            services.AddSingleton<MockOAuth2HttpClient>(MockHttpClient);

            // Register auth configuration and services
            services.AddSingleton(Config);
            services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
            services.AddTransient<IAuthLogger, ConsoleAuthLogger>();
            services.AddTransient<AuthClient>();

            // Allow derived classes to customize services
            ConfigureServices(services);

            ServiceProvider = services.BuildServiceProvider();
        }        protected AuthClient CreateAuthClient(AuthClientConfig? customConfig = null)
        {
            var config = customConfig ?? Config;
            var httpClient = ServiceProvider.GetRequiredService<ICoyoteHttpClient>();
            var tokenStorage = ServiceProvider.GetRequiredService<IAuthTokenStorage>();
            var logger = ServiceProvider.GetRequiredService<IAuthLogger>();
            
            return new AuthClient(config, httpClient, tokenStorage, logger);
        }

        protected AuthClient CreateAuthClientWithNullableConfig(AuthClientConfig? config)
        {
            var httpClient = ServiceProvider.GetRequiredService<ICoyoteHttpClient>();
            var tokenStorage = ServiceProvider.GetRequiredService<IAuthTokenStorage>();
            var logger = ServiceProvider.GetRequiredService<IAuthLogger>();
            
            return new AuthClient(config!, httpClient, tokenStorage, logger);
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
