using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Multi-standard authentication modes supported by the platform
/// </summary>
public enum AuthMode
{    /// <summary>
     /// Standard OAuth2 client credentials flow (RFC 6749)
     /// </summary>
    ClientCredentials,

    /// <summary>
    /// Client credentials with mutual TLS authentication (RFC 8705)
    /// </summary>
    ClientCredentialsMtls,

    /// <summary>
    /// JWT Bearer assertion flow (RFC 7523)
    /// </summary>
    JwtBearer,

    /// <summary>
    /// Authorization code flow (RFC 6749)
    /// </summary>
    AuthorizationCode,

    /// <summary>
    /// Authorization code flow with PKCE (RFC 7636)
    /// </summary>
    AuthorizationCodePkce
}

/// <summary>
/// Authentication token storage interface
/// </summary>
public interface IAuthTokenStorage
{
    /// <summary>
    /// Store a token for a client
    /// </summary>
    Task StoreTokenAsync(string clientId, AuthToken token);

    /// <summary>
    /// Retrieve a token for a client
    /// </summary>
    AuthToken? GetToken(string clientId);

    /// <summary>
    /// Clear stored token for a client
    /// </summary>
    void ClearToken(string clientId);

    /// <summary>
    /// Clear all stored tokens
    /// </summary>
    void ClearAllTokens();
}

/// <summary>
/// Authentication logger interface
/// </summary>
public interface IAuthLogger
{
    /// <summary>
    /// Log information message
    /// </summary>
    void LogInfo(string message);

    /// <summary>
    /// Log error message
    /// </summary>
    void LogError(string message);

    /// <summary>
    /// Log debug message
    /// </summary>
    void LogDebug(string message);
}

/// <summary>
/// In-memory token storage implementation
/// </summary>
public class InMemoryTokenStorage : IAuthTokenStorage
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, AuthToken> _tokens = new();

    /// <summary>
    /// Stores an authentication token for the specified client
    /// </summary>
    public Task StoreTokenAsync(string clientId, AuthToken token)
    {
        _tokens[clientId] = token;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Retrieves the stored token for the specified client
    /// </summary>
    public AuthToken? GetToken(string clientId)
    {
        return _tokens.TryGetValue(clientId, out var token) ? token : null;
    }

    /// <summary>
    /// Clears the stored token for the specified client
    /// </summary>
    public void ClearToken(string clientId)
    {
        _tokens.TryRemove(clientId, out _);
    }

    /// <summary>
    /// Clears all stored tokens
    /// </summary>
    public void ClearAllTokens()
    {
        _tokens.Clear();
    }
}

/// <summary>
/// Console logger implementation
/// </summary>
public class ConsoleAuthLogger : IAuthLogger
{
    private readonly string _prefix;

    /// <summary>
    /// Initializes a new instance of the ConsoleAuthLogger
    /// </summary>
    public ConsoleAuthLogger(string? prefix = null)
    {
        _prefix = prefix ?? "Auth";
    }

    /// <summary>
    /// Logs an informational message to the console
    /// </summary>
    public void LogInfo(string message)
    {
        Console.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] [{_prefix}] INFO: {message}");
    }

    /// <summary>
    /// Logs an error message to the console
    /// </summary>
    public void LogError(string message)
    {
        Console.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] [{_prefix}] ERROR: {message}");
    }

    /// <summary>
    /// Logs a debug message to the console
    /// </summary>
    public void LogDebug(string message)
    {
        Console.WriteLine($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] [{_prefix}] DEBUG: {message}");
    }
}

/// <summary>
/// Null logger implementation (no logging)
/// </summary>
public class NullAuthLogger : IAuthLogger
{
    /// <summary>
    /// Logs an informational message (no-op)
    /// </summary>
    public void LogInfo(string message) { }

    /// <summary>
    /// Logs an error message (no-op)
    /// </summary>
    public void LogError(string message) { }

    /// <summary>
    /// Logs a debug message (no-op)
    /// </summary>
    public void LogDebug(string message) { }
}

/// <summary>
/// Authentication token information
/// </summary>
public class AuthToken
{
    /// <summary>
    /// Access token
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Token type (usually "Bearer")
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Token expiration time
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Refresh token (if available)
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Token scopes
    /// </summary>
    public List<string> Scopes { get; set; } = new();

    /// <summary>
    /// Check if token is expired
    /// </summary>
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;

    /// <summary>
    /// Check if token needs refresh (within buffer time)
    /// </summary>
    public bool NeedsRefresh(int bufferSeconds = 300) => DateTime.UtcNow.AddSeconds(bufferSeconds) >= ExpiresAt;

    /// <summary>
    /// Get authorization header value
    /// </summary>
    public string GetAuthorizationHeader() => $"{TokenType} {AccessToken}";
}

/// <summary>
/// Authentication result
/// </summary>
public class AuthResult
{
    /// <summary>
    /// Whether authentication was successful
    /// </summary>
    public bool IsSuccess { get; set; }

    /// <summary>
    /// Authentication token (if successful)
    /// </summary>
    public AuthToken? Token { get; set; }

    /// <summary>
    /// Error code (if failed)
    /// </summary>
    public string? ErrorCode { get; set; }

    /// <summary>
    /// Error description (if failed)
    /// </summary>
    public string? ErrorDescription { get; set; }

    /// <summary>
    /// Additional error details
    /// </summary>
    public string? ErrorDetails { get; set; }

    /// <summary>
    /// Create success result
    /// </summary>
    public static AuthResult Success(AuthToken token) => new()
    {
        IsSuccess = true,
        Token = token
    };

    /// <summary>
    /// Create error result
    /// </summary>
    public static AuthResult Error(string errorCode, string? errorDescription = null, string? errorDetails = null) => new()
    {
        IsSuccess = false,
        ErrorCode = errorCode,
        ErrorDescription = errorDescription,
        ErrorDetails = errorDetails
    };
}

/// <summary>
/// Authentication server information
/// </summary>
public class AuthServerInfo
{
    /// <summary>
    /// Authorization endpoint URL
    /// </summary>
    public string AuthorizationEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Token endpoint URL
    /// </summary>
    public string TokenEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Token introspection endpoint URL
    /// </summary>
    public string? IntrospectionEndpoint { get; set; }

    /// <summary>
    /// Token revocation endpoint URL
    /// </summary>
    public string? RevocationEndpoint { get; set; }

    /// <summary>
    /// Supported grant types
    /// </summary>
    public List<string> GrantTypesSupported { get; set; } = new();

    /// <summary>
    /// Supported scopes
    /// </summary>
    public List<string> ScopesSupported { get; set; } = new();
}
