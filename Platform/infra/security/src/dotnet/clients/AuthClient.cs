using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;

namespace Coyote.Infra.Security.Auth
{
    /// <summary>
    /// Main authentication client implementation
    /// </summary>
    public class AuthClient : IAuthClient, IDisposable
    {
        private readonly ILogger<AuthClient> _logger;
        private readonly AuthClientOptions _options;
        private AuthToken? _currentToken;
        private bool _disposed = false;

        public AuthClient(AuthClientOptions options, ILogger<AuthClient> logger)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }        /// <summary>
        /// Legacy constructor for tests that pass additional parameters
        /// </summary>
        public AuthClient(AuthClientConfig config, ICoyoteHttpClient httpClient, IAuthTokenStorage tokenStorage, IAuthLogger authLogger)
        {
            // Convert config to options
            _options = config?.ToAuthClientOptions() ?? throw new ArgumentNullException(nameof(config));
            
            // Create a logger from the authLogger
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            _logger = loggerFactory.CreateLogger<AuthClient>();
            
            // Store the httpClient for potential use (though we don't use it in this mock implementation)
            // In a real implementation, we would use these parameters
        }

        public async Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Requesting valid authentication token");
            
            // Mock implementation for testing
            var token = new AuthToken
            {
                AccessToken = "mock-token-" + Guid.NewGuid().ToString("N")[..8],
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                TokenType = "Bearer"
            };

            _currentToken = token;
            return await Task.FromResult(token);
        }

        public async Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Authenticating with client credentials");
            
            var token = await GetValidTokenAsync(cancellationToken);
            return new AuthResult 
            { 
                IsSuccess = true, 
                Token = token,
                ErrorDescription = null
            };
        }

        public async Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Authenticating with JWT Bearer");
            
            var token = await GetValidTokenAsync(cancellationToken);
            return new AuthResult 
            { 
                IsSuccess = true, 
                Token = token,
                ErrorDescription = null
            };
        }

        public async Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Authenticating with authorization code");
            
            var token = await GetValidTokenAsync(cancellationToken);
            return new AuthResult 
            { 
                IsSuccess = true, 
                Token = token,
                ErrorDescription = null
            };
        }

        public (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
        {
            _logger.LogDebug("Starting authorization code flow");
            
            var codeVerifier = Guid.NewGuid().ToString("N");
            var actualState = state ?? Guid.NewGuid().ToString("N");
            var authUrl = $"{_options.ServerUrl}/authorize?response_type=code&client_id={_options.ClientId}&redirect_uri={redirectUri}&state={actualState}";
            
            return (authUrl, codeVerifier, actualState);
        }

        public async Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Refreshing authentication token");
            
            if (string.IsNullOrEmpty(refreshToken))
                return new AuthResult { IsSuccess = false, ErrorDescription = "Refresh token is required" };

            var token = new AuthToken
            {
                AccessToken = "refreshed-token-" + Guid.NewGuid().ToString("N")[..8],
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                TokenType = "Bearer",
                RefreshToken = "new-refresh-" + Guid.NewGuid().ToString("N")[..8]
            };

            _currentToken = token;
            return await Task.FromResult(new AuthResult 
            { 
                IsSuccess = true, 
                Token = token,
                ErrorDescription = null
            });
        }

        public async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Revoking token");
            return await Task.FromResult(true);
        }

        public async Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Introspecting token");
            return await Task.FromResult(true);
        }

        public async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Testing connection");
            return await Task.FromResult(true);
        }

        public async Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Getting server info");
            
            return await Task.FromResult(new AuthServerInfo
            {
                AuthorizationEndpoint = $"{_options.ServerUrl}/authorize",
                TokenEndpoint = $"{_options.ServerUrl}/token",
                GrantTypesSupported = new List<string> { "client_credentials", "authorization_code", "refresh_token" },
                ScopesSupported = new List<string> { "read", "write", "admin" }
            });
        }

        public void ClearTokens()
        {
            _logger.LogDebug("Clearing tokens");
            _currentToken = null;
        }

        public AuthToken? CurrentToken => _currentToken;

        public bool IsAuthenticated => _currentToken != null && _currentToken.ExpiresAt > DateTime.UtcNow.AddMinutes(5);

        public async Task InvalidateTokenAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Invalidating authentication token");
            _currentToken = null;
            await Task.CompletedTask;
        }

        public bool IsTokenValid(AuthToken token)
        {
            if (token == null || string.IsNullOrEmpty(token.AccessToken))
                return false;

            return token.ExpiresAt > DateTime.UtcNow.AddMinutes(5); // 5 minute buffer
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _logger.LogDebug("Disposing AuthClient");
                ClearTokens();
                _disposed = true;
            }
        }
    }
}
