using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Multi-standard authentication client interface supporting OAuth2 (RFC 6749), 
/// JWT Bearer (RFC 7523), and mTLS (RFC 8705) authentication methods.
/// 
/// This interface provides a unified API for multiple authentication standards:
/// - OAuth2 Client Credentials (RFC 6749)
/// - OAuth2 Authorization Code (RFC 6749) 
/// - JWT Bearer Token (RFC 7523)
/// - Mutual TLS (RFC 8705)
/// </summary>
public interface IAuthClient : IDisposable
{    /// <summary>
    /// Authenticate using Client Credentials flow (OAuth2 RFC 6749)
    /// </summary>
    Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticate using JWT Bearer flow (RFC 7523)
    /// </summary>
    Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticate using Authorization Code flow (OAuth2 RFC 6749)
    /// </summary>
    Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Start Authorization Code + PKCE flow (OAuth2 RFC 7636)
    /// </summary>
    Task<(string authorizationUrl, string codeVerifier, string state)> StartAuthorizationCodeFlowAsync(string redirectUri, List<string>? scopes = null, string? state = null);    /// <summary>
    /// Refresh access token using refresh token
    /// </summary>
    Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get current valid token (automatically refreshes if needed)
    /// </summary>
    Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Revoke a token
    /// </summary>
    Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default);    /// <summary>
    /// Introspect a token
    /// </summary>
    Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Test connection to authentication server
    /// </summary>
    Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Get authentication server information
    /// </summary>
    Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Clear stored tokens
    /// </summary>
    void ClearTokens();    /// <summary>
    /// Current token (if any)
    /// </summary>
    AuthToken? CurrentToken { get; }

    /// <summary>
    /// Whether client has valid authentication
    /// </summary>
    bool IsAuthenticated { get; }    // Synchronous versions for compatibility
    AuthResult AuthenticateClientCredentials(List<string>? scopes = null);
    AuthResult AuthenticateJwtBearer(string? subject = null, List<string>? scopes = null);
    AuthResult AuthenticateAuthorizationCode(string authorizationCode, string redirectUri, string? codeVerifier = null);
    AuthResult RefreshToken(string refreshToken);
    AuthToken? GetValidToken();
    bool RevokeToken(string token, string? tokenTypeHint = null);
    bool IntrospectToken(string token);
    bool TestConnection();
    AuthServerInfo? GetServerInfo();
}
