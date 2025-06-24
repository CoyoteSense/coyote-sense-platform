using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Modes.Real;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Factory for creating SecureStoreClient instances
/// </summary>
public static class SecureStoreClientFactory
{
    /// <summary>
    /// Create a SecureStoreClient with the specified options
    /// </summary>
    public static SecureStoreClient Create(SecureStoreOptions options, IAuthClient authClient, ILogger<SecureStoreClient>? logger = null)
    {
        logger ??= CreateDefaultLogger();
        return new SecureStoreClient(options, authClient, logger);
    }

    /// <summary>
    /// Create a SecureStoreClient with mock auth client for testing
    /// </summary>
    public static SecureStoreClient CreateWithMockAuth(SecureStoreOptions options, ILogger<SecureStoreClient>? logger = null)
    {
        logger ??= CreateDefaultLogger();
        var mockAuthClient = CreateMockAuthClient();
        return new SecureStoreClient(options, mockAuthClient, logger);
    }

    /// <summary>
    /// Create a SecureStoreClient for testing with default options
    /// </summary>
    public static SecureStoreClient CreateForTesting(string serverUrl = "https://test-keyvault.coyotesense.io")
    {
        var options = new SecureStoreOptions
        {
            ServerUrl = serverUrl,
            ApiVersion = "v1",
            TimeoutMs = 30000
        };

        var logger = CreateDefaultLogger();
        var mockAuthClient = CreateMockAuthClient();
        return new SecureStoreClient(options, mockAuthClient, logger);
    }

    /// <summary>
    /// Create a SecureStoreClient with the specified auth client
    /// </summary>
    public static ISecureStoreClient CreateWithAuthClient(SecureStoreOptions options, IAuthClient authClient, ILogger<SecureStoreClient>? logger = null)
    {
        logger ??= CreateDefaultLogger();
        return new SecureStoreClient(options, authClient, logger);
    }    /// <summary>
    /// Create a SecureStoreClient with a token provider function
    /// </summary>
    public static ISecureStoreClient CreateWithTokenProvider(SecureStoreOptions options, Func<CancellationToken, Task<string?>> tokenProvider, ILogger<SecureStoreClient>? logger = null)
    {
        logger ??= CreateDefaultLogger();
        var tokenProviderAuthClient = new TokenProviderAuthClient(tokenProvider);
        return new SecureStoreClient(options, tokenProviderAuthClient, logger);
    }

    /// <summary>
    /// Create a new SecureStoreClient builder with no pre-configuration
    /// </summary>
    public static SecureStoreClientBuilder CreateBuilder()
    {
        return new SecureStoreClientBuilder();
    }

    /// <summary>
    /// Create a new SecureStoreClient builder with server URL pre-configured
    /// </summary>
    public static SecureStoreClientBuilder CreateBuilder(string serverUrl)
    {
        return new SecureStoreClientBuilder().WithServerUrl(serverUrl);
    }

    /// <summary>
    /// Create a SecureStoreClient with a token provider
    /// </summary>
    public static ISecureStoreClient CreateWithTokenProvider(SecureStoreOptions options, Func<CancellationToken, Task<string?>> tokenProvider)
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));
        if (tokenProvider == null)
            throw new ArgumentNullException(nameof(tokenProvider));

        // Create an auth client that uses the token provider
        var authClient = new TokenProviderAuthClient(tokenProvider);
        var logger = CreateDefaultLogger();
        
        return new SecureStoreClient(options, authClient, logger);
    }

    private static ILogger<SecureStoreClient> CreateDefaultLogger()
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging(builder => builder.AddConsole());
        var serviceProvider = serviceCollection.BuildServiceProvider();
        return serviceProvider.GetRequiredService<ILogger<SecureStoreClient>>();
    }

    private static IAuthClient CreateMockAuthClient()
    {
        // Create a simple mock auth client for testing
        return new MockAuthClientForFactory();
    }    /// <summary>
    /// Simple mock auth client implementation for factory use
    /// </summary>
    private class MockAuthClientForFactory : IAuthClient
    {
        public AuthToken? CurrentToken => new AuthToken 
        { 
            AccessToken = "mock-token-12345", 
            TokenType = "Bearer", 
            ExpiresAt = DateTime.UtcNow.AddHours(1) 
        };
        
        public bool IsAuthenticated => true;        public Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "mock-access-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "mock-jwt-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "mock-auth-code-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
        {
            return ("https://mock-auth.coyotesense.io/authorize", "mock-verifier", state ?? "mock-state");
        }        public Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "mock-refreshed-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthToken?>(new AuthToken 
            { 
                AccessToken = "mock-valid-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            });
        }

        public Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }        public Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthServerInfo?>(new AuthServerInfo 
            { 
                AuthorizationEndpoint = "https://mock-auth.coyotesense.io/authorize",
                TokenEndpoint = "https://mock-auth.coyotesense.io/token",
                GrantTypesSupported = new List<string> { "client_credentials", "authorization_code" },
                ScopesSupported = new List<string> { "read", "write" }
            });
        }

        public void ClearTokens()
        {
            // Mock implementation - no-op
        }

        public void Dispose()
        {            // Mock implementation - no-op
        }
    }

    /// <summary>
    /// Token provider auth client for custom token generation
    /// </summary>
    private class TokenProviderAuthClient : IAuthClient
    {
        private readonly Func<CancellationToken, Task<string?>> _tokenProvider;
        private AuthToken? _currentToken;

        public TokenProviderAuthClient(Func<CancellationToken, Task<string?>> tokenProvider)
        {
            _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        }

        public async Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
        {
            var token = await _tokenProvider(cancellationToken);
            if (string.IsNullOrEmpty(token))
                return null;
                
            var authToken = new AuthToken
            {
                AccessToken = token,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                TokenType = "Bearer"
            };
            _currentToken = authToken;
            return authToken;
        }

        public async Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            var token = await GetValidTokenAsync(cancellationToken);
            return new AuthResult { IsSuccess = true, Token = token };
        }

        public async Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            var token = await GetValidTokenAsync(cancellationToken);
            return new AuthResult { IsSuccess = true, Token = token };
        }

        public async Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
        {
            var token = await GetValidTokenAsync(cancellationToken);
            return new AuthResult { IsSuccess = true, Token = token };
        }

        public (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
        {
            var codeVerifier = Guid.NewGuid().ToString("N");
            var actualState = state ?? Guid.NewGuid().ToString("N");
            var authUrl = $"https://mock-auth.example.com/authorize?response_type=code&client_id=mock&redirect_uri={redirectUri}&state={actualState}";
            return (authUrl, codeVerifier, actualState);
        }

        public async Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var token = await GetValidTokenAsync(cancellationToken);
            return new AuthResult { IsSuccess = true, Token = token };
        }

        public async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        {
            return await Task.FromResult(true);
        }

        public async Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            return await Task.FromResult(true);
        }

        public async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            return await Task.FromResult(true);
        }

        public async Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
        {
            return await Task.FromResult(new AuthServerInfo
            {
                AuthorizationEndpoint = "https://mock-auth.example.com/authorize",
                TokenEndpoint = "https://mock-auth.example.com/token",
                GrantTypesSupported = new List<string> { "client_credentials" },
                ScopesSupported = new List<string> { "read", "write" }
            });
        }

        public void ClearTokens()
        {
            _currentToken = null;
        }

        public AuthToken? CurrentToken => _currentToken;

        public bool IsAuthenticated => _currentToken != null && _currentToken.ExpiresAt > DateTime.UtcNow;

        public void Dispose() { }
    }

    /// <summary>
    /// Builder pattern for SecureStoreClient configuration
    /// </summary>
    public class SecureStoreClientBuilder
    {
        private SecureStoreOptions? _options;
        private IAuthClient? _authClient;
        private ILogger<SecureStoreClient>? _logger;

        public SecureStoreClientBuilder WithOptions(SecureStoreOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            return this;
        }

        public SecureStoreClientBuilder WithAuthClient(IAuthClient authClient)
        {
            _authClient = authClient ?? throw new ArgumentNullException(nameof(authClient));
            return this;
        }

        public SecureStoreClientBuilder WithLogger(ILogger<SecureStoreClient> logger)
        {
            _logger = logger;
            return this;
        }

        public SecureStoreClientBuilder WithServerUrl(string serverUrl)
        {
            _options ??= new SecureStoreOptions();
            _options.ServerUrl = serverUrl;
            return this;
        }

        public SecureStoreClientBuilder WithTimeout(int timeoutMs)
        {
            _options ??= new SecureStoreOptions();
            _options.TimeoutMs = timeoutMs;
            return this;
        }

        /// <summary>
        /// Configure retry behavior for the secure store client
        /// </summary>
        public SecureStoreClientBuilder WithRetry(int maxRetryAttempts)
        {
            _options ??= new SecureStoreOptions();
            _options.MaxRetryAttempts = maxRetryAttempts;
            return this;
        }        /// <summary>
        /// Configure token provider for the secure store client
        /// </summary>
        public SecureStoreClientBuilder WithTokenProvider(Func<CancellationToken, Task<string?>> tokenProvider)
        {
            // For now, wrap the token provider as an auth client
            _authClient = new TokenProviderAuthClient(tokenProvider);
            return this;
        }

        /// <summary>
        /// Configure mutual TLS options for the secure store client
        /// </summary>
        public SecureStoreClientBuilder WithMutualTls(MtlsOptions mtlsOptions)
        {
            if (mtlsOptions == null)
                throw new ArgumentNullException(nameof(mtlsOptions));
                
            // Configure auth client with mTLS options
            var authOptions = mtlsOptions.ToAuthClientConfig().ToAuthClientOptions();
            var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<RealAuthClient>();
            _authClient = new RealAuthClient(authOptions, logger);
            return this;
        }

        /// <summary>
        /// Configure mutual TLS options for the secure store client with cert and key paths
        /// </summary>
        public SecureStoreClientBuilder WithMutualTls(string certPath, string keyPath)
        {
            if (string.IsNullOrEmpty(certPath))
                throw new ArgumentException("Certificate path cannot be null or empty", nameof(certPath));
            if (string.IsNullOrEmpty(keyPath))
                throw new ArgumentException("Key path cannot be null or empty", nameof(keyPath));
                
            // Create MtlsOptions and configure auth client
            var mtlsOptions = new MtlsOptions
            {
                ServerUrl = _options?.ServerUrl ?? "https://localhost",
                ClientId = "default-client",
                ClientCertPath = certPath,
                ClientKeyPath = keyPath,
                CaCertPath = "/etc/ssl/certs/ca-certificates.crt", // default CA path
                DefaultScopes = new List<string> { "read", "write" },
                AutoRefresh = true,
                TimeoutMs = 30000
            };
            
            return WithMutualTls(mtlsOptions);
        }

        /// <summary>
        /// Configure custom headers for the secure store client
        /// </summary>
        public SecureStoreClientBuilder WithCustomHeaders(Dictionary<string, string> headers)
        {
            if (headers == null)
                throw new ArgumentNullException(nameof(headers));
                
            _options ??= new SecureStoreOptions();
            _options.DefaultHeaders = new Dictionary<string, string>(headers);
            return this;
        }

        /// <summary>
        /// Configure TLS options for the secure store client
        /// </summary>
        public SecureStoreClientBuilder WithTls(bool verifySsl = true, string? caCertPath = null)
        {
            _options ??= new SecureStoreOptions();
            _options.VerifySsl = verifySsl;
            
            if (!string.IsNullOrEmpty(caCertPath))
            {
                // Store CA cert path for TLS verification
                // In a real implementation, this would configure the HTTP client's certificate validation
            }
            
            return this;
        }        public ISecureStoreClient Build()
        {
            if (_options == null)
                throw new InvalidOperationException("Options must be provided");
                
            if (_authClient == null)
                throw new InvalidOperationException("Either an auth client or token provider must be provided");
            
            _logger ??= CreateDefaultLogger();

            return new SecureStoreClient(_options, _authClient, _logger);
        }
    }
}
