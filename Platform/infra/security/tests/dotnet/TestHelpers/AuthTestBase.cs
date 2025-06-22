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
                var tokenStorage = provider.GetRequiredService<IAuthTokenStorage>();
                return new Coyote.Infra.Security.Auth.AuthClient(config, msLogger, httpClient, tokenStorage);
            });            // Register SecureStoreClient for tests that need it
            services.AddTransient<SecureStoreClient>(provider =>
            {
                var config = provider.GetRequiredService<AuthClientConfig>();
                var authLogger = provider.GetRequiredService<ILogger<AuthClient>>();
                var httpClient = provider.GetRequiredService<ICoyoteHttpClient>();
                var tokenStorage = provider.GetRequiredService<IAuthTokenStorage>();
                var authClient = new Coyote.Infra.Security.Auth.AuthClient(config, authLogger, httpClient, tokenStorage);
                
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

            // Use the real AuthClient from modes/real/dotnet that actually uses the HTTP client
            return new Coyote.Infra.Security.Auth.AuthClient(config, msLogger, httpClient, tokenStorage);
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
