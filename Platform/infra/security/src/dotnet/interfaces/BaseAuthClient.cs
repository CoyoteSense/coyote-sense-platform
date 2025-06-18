using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Base authentication client providing common functionality
/// </summary>
public abstract class BaseAuthClient : IAuthClient
{
    protected readonly AuthClientOptions _options;
    protected readonly ILogger _logger;
    protected AuthToken? _currentToken;
    protected readonly object _tokenLock = new object();
    protected bool _disposed = false;

    protected BaseAuthClient(AuthClientOptions options, ILogger logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        // Validate configuration
        _options.Validate();
    }

    /// <summary>
    /// Get configuration for logging/debugging
    /// </summary>
    public AuthClientOptions Options => _options;

    /// <summary>
    /// Log debug information if debug logging is enabled
    /// </summary>
    protected void LogDebug(string message, params object[] args)
    {
        if (_options.EnableDebugLogging)
        {
            _logger.LogDebug(message, args);
        }
    }

    /// <summary>
    /// Check if current token is valid and not expired
    /// </summary>
    protected bool IsTokenValid()
    {
        lock (_tokenLock)
        {
            if (_currentToken == null)
                return false;            // Check if token expires soon (within 30 seconds)
            var now = DateTimeOffset.UtcNow;
            var expiresAt = new DateTimeOffset(_currentToken.ExpiresAt, TimeSpan.Zero);
            return expiresAt > now.AddSeconds(30);
        }
    }

    /// <summary>
    /// Store token thread-safely
    /// </summary>
    protected void StoreToken(AuthToken token)
    {
        lock (_tokenLock)
        {
            _currentToken = token;
            LogDebug("Token stored, expires at: {ExpiresAt}", token.ExpiresAt);
        }
    }    // Abstract methods that implementations must provide
    public abstract Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default);
    public abstract Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default);
    public abstract Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default);
    public abstract (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null);
    public abstract Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);
    public abstract Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default);
    public abstract Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default);
    public abstract Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default);
    public abstract Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default);
    public abstract void ClearTokens();
    public abstract AuthToken? CurrentToken { get; }
    public abstract bool IsAuthenticated { get; }

    /// <summary>
    /// Get current valid token (automatically refreshes if needed)
    /// </summary>
    public virtual async Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
    {
        if (IsTokenValid())
        {
            return _currentToken;
        }

        // Try to refresh if we have a refresh token
        if (_currentToken?.RefreshToken != null)
        {
            try
            {
                var refreshResult = await RefreshTokenAsync(_currentToken.RefreshToken, cancellationToken);
                if (refreshResult.IsSuccess && refreshResult.Token != null)
                {
                    StoreToken(refreshResult.Token);
                    return refreshResult.Token;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to refresh token");
            }
        }

        // Fall back to re-authentication using client credentials
        try
        {
            var authResult = await AuthenticateClientCredentialsAsync(cancellationToken: cancellationToken);
            if (authResult.IsSuccess && authResult.Token != null)
            {
                StoreToken(authResult.Token);
                return authResult.Token;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to authenticate");
        }

        return null;
    }    /// <summary>
    /// Dispose resources
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Dispose pattern implementation
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed resources
                ClearTokens();
            }
            _disposed = true;
        }
    }
}
