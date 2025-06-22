using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Modes.Real;
using Coyote.Infra.Security.Auth.Security;
using Coyote.Infra.Http.Factory;

namespace Coyote.Infra.Security.Tests.TestHelpers
{
    /// <summary>
    /// Test wrapper for AuthClientFactory to work around compilation issues
    /// </summary>
    public static class TestAuthClientFactory
    {
        /// <summary>
        /// Create auth client from MtlsOptions for tests
        /// </summary>
        public static IAuthClient CreateFromOptions(MtlsOptions options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var config = options.ToAuthClientConfig().ToAuthClientOptions();
            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(config, logger);
        }

        /// <summary>
        /// Create auth client from AuthClientOptions for tests
        /// </summary>
        public static IAuthClient CreateFromOptions(AuthClientOptions options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(options, logger);
        }

        /// <summary>
        /// Create auth client with secure credentials for tests
        /// </summary>
        public static IAuthClient CreateWithSecureCredentials(string serverUrl, string credentialPath, List<string>? scopes = null)
        {
            var options = new AuthClientOptions
            {
                ServerUrl = serverUrl,
                ClientId = "test-client",
                DefaultScopes = scopes ?? new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(options, logger);
        }

        /// <summary>
        /// Create auth client with secure credentials for tests - overload for AuthClientConfig
        /// </summary>  
        public static IAuthClient CreateWithSecureCredentials(AuthClientConfig config, SecureCredentialProvider credentialProvider)
        {
            var options = new AuthClientOptions
            {
                ServerUrl = config.ServerUrl,
                ClientId = config.ClientId,
                ClientSecret = credentialProvider.GetClientSecret(),
                DefaultScopes = new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(options, logger);
        }

        /// <summary>
        /// Create auth client from ClientCredentialsOptions for tests
        /// </summary>
        public static IAuthClient CreateFromOptions(ClientCredentialsOptions options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var authOptions = new AuthClientOptions
            {
                ServerUrl = options.ServerUrl,
                ClientId = options.ClientId,
                ClientSecret = options.ClientSecret,
                DefaultScopes = options.DefaultScopes ?? new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(authOptions, logger);
        }        /// <summary>
        /// Create auth client from JwtBearerOptions for tests
        /// </summary>
        public static IAuthClient CreateFromOptions(JwtBearerOptions options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var authOptions = new AuthClientOptions
            {
                Mode = AuthMode.JwtBearer,
                ServerUrl = options.ServerUrl,
                ClientId = options.ClientId,
                JwtSigningKeyPath = options.JwtSigningKeyPath,
                JwtIssuer = options.JwtIssuer,
                JwtAudience = options.JwtAudience,
                DefaultScopes = options.DefaultScopes ?? new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(authOptions, logger);        }
        
        /// <summary>
        /// Create client credentials client for tests
        /// </summary>
        public static IAuthClient CreateClientCredentialsClient(string serverUrl, string clientId, string clientSecret, List<string>? defaultScopes = null)
        {            var options = new AuthClientOptions
            {
                Mode = AuthMode.ClientCredentials,
                ServerUrl = serverUrl,
                ClientId = clientId,
                ClientSecret = clientSecret,
                DefaultScopes = defaultScopes ?? new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(options, logger);
        }        /// <summary>
        /// Create JWT Bearer client for tests
        /// </summary>
        public static IAuthClient CreateJwtBearerClient(string serverUrl, string clientId, string? jwtSigningKeyPath = null, string? jwtIssuer = null, string? jwtAudience = null, List<string>? defaultScopes = null)
        {
            var options = new AuthClientOptions
            {
                Mode = AuthMode.JwtBearer,
                ServerUrl = serverUrl,
                ClientId = clientId,
                JwtSigningKeyPath = jwtSigningKeyPath,
                JwtIssuer = jwtIssuer,
                JwtAudience = jwtAudience,
                DefaultScopes = defaultScopes ?? new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(options, logger);
        }
        
        /// <summary>
        /// Create Authorization Code client for tests
        /// </summary>
        public static IAuthClient CreateAuthorizationCodeClient(string serverUrl, string clientId, string? clientSecret = null, string? redirectUri = null, List<string>? scopes = null)
        {            var options = new AuthClientOptions
            {
                Mode = AuthMode.AuthorizationCode,
                ServerUrl = serverUrl,
                ClientId = clientId,
                ClientSecret = clientSecret,
                DefaultScopes = scopes ?? new List<string> { "read", "write" },
                TimeoutMs = 30000,
                AutoRefresh = true
            };

            var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
            var logger = loggerFactory.CreateLogger<RealAuthClient>();
            
            return new RealAuthClient(options, logger);
        }

        /// <summary>
        /// Get default HTTP client for testing
        /// </summary>
        public static HttpClient GetDefaultHttpClient()
        {
            return new HttpClient { Timeout = TimeSpan.FromSeconds(30) };        }
          /// <summary>
        /// Set HTTP client factory for tests (no-op for testing)
        /// </summary>
        public static void SetHttpClientFactory(Coyote.Infra.Http.Factory.IHttpClientFactory factory)
        {
            // Store factory reference for later use in tests
            // In real implementation, this would configure the factory
        }
    }
}
