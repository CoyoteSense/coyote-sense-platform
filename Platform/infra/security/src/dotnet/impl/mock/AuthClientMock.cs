using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Coyote.Infra.Security.Auth.Modes.Mock;

/// <summary>
/// Mock authentication client for testing and development
/// </summary>
public class MockAuthClient : BaseAuthClient
{
    private readonly new ILogger<MockAuthClient> _logger;

    public MockAuthClient(AuthClientOptions options, ILogger<MockAuthClient> logger)
        : base(options, logger)
    {
        _logger = logger;
        LogDebug("MockAuthClient initialized for testing/development");
    }

    public override async Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
    {        LogDebug("Mock: AuthenticateClientCredentialsAsync called with scopes: {Scopes}", scopes != null ? string.Join(", ", scopes) : "none");
        
        await Task.Delay(50, cancellationToken); // Simulate network delay

        var token = new AuthToken
        {
            AccessToken = $"mock_access_token_{Guid.NewGuid():N}",
            TokenType = "Bearer",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).DateTime,
            Scopes = scopes ?? new List<string> { "default" },
            RefreshToken = $"mock_refresh_token_{Guid.NewGuid():N}"
        };

        StoreToken(token);

        return new AuthResult
        {
            IsSuccess = true,
            Token = token,
            ErrorDescription = null
        };
    }

    public override async Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        LogDebug("Mock: AuthenticateJwtBearerAsync called with subject: {Subject}, scopes: {Scopes}", 
            subject ?? "none", scopes != null ? string.Join(", ", scopes) : "none");
        
        await Task.Delay(50, cancellationToken);        var token = new AuthToken
        {
            AccessToken = $"mock_jwt_token_{Guid.NewGuid():N}",
            TokenType = "Bearer",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).DateTime,
            Scopes = scopes ?? new List<string> { "default" }
        };

        StoreToken(token);

        return new AuthResult
        {
            IsSuccess = true,
            Token = token,
            ErrorDescription = null
        };
    }

    public override async Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
    {
        LogDebug("Mock: AuthenticateAuthorizationCodeAsync called with code: {Code}, redirectUri: {RedirectUri}", 
            authorizationCode, redirectUri);
        
        await Task.Delay(50, cancellationToken);

        if (string.IsNullOrWhiteSpace(authorizationCode))
        {
            return new AuthResult
            {
                IsSuccess = false,
                ErrorCode = "invalid_request",
                ErrorDescription = "Authorization code is required"
            };
        }        var token = new AuthToken
        {
            AccessToken = $"mock_auth_code_token_{Guid.NewGuid():N}",
            TokenType = "Bearer",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).DateTime,
            RefreshToken = $"mock_refresh_token_{Guid.NewGuid():N}",
            Scopes = new List<string> { "read", "write" }
        };

        StoreToken(token);

        return new AuthResult
        {
            IsSuccess = true,
            Token = token,
            ErrorDescription = null
        };
    }

    public override (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
    {
        LogDebug("Mock: StartAuthorizationCodeFlow called with redirectUri: {RedirectUri}", redirectUri);

        var actualState = state ?? Guid.NewGuid().ToString("N");
        var codeVerifier = Guid.NewGuid().ToString("N");
        var scopeParam = scopes != null ? string.Join(" ", scopes) : "read";

        var authUrl = $"{_options.ServerUrl}/oauth/authorize" +
                     $"?client_id={_options.ClientId}" +
                     $"&response_type=code" +
                     $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                     $"&scope={Uri.EscapeDataString(scopeParam)}" +
                     $"&state={actualState}" +
                     "&code_challenge_method=S256" +
                     $"&code_challenge=mock_challenge";

        return (authUrl, codeVerifier, actualState);
    }

    public override async Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        LogDebug("Mock: RefreshTokenAsync called");
        
        await Task.Delay(50, cancellationToken);

        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return new AuthResult
            {
                IsSuccess = false,
                ErrorCode = "invalid_request",
                ErrorDescription = "Refresh token is required"
            };
        }        var token = new AuthToken
        {
            AccessToken = $"mock_refreshed_token_{Guid.NewGuid():N}",
            TokenType = "Bearer",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).DateTime,
            RefreshToken = $"mock_new_refresh_token_{Guid.NewGuid():N}",
            Scopes = new List<string> { "read", "write" }
        };

        StoreToken(token);

        return new AuthResult
        {
            IsSuccess = true,
            Token = token,
            ErrorDescription = null
        };
    }    public override async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        LogDebug("Mock: RevokeTokenAsync called");
        
        await Task.Delay(50, cancellationToken);

        // Always succeed in mock mode
        return true;
    }

    public override async Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        LogDebug("Mock: IntrospectTokenAsync called");
        
        await Task.Delay(50, cancellationToken);

        // Always return true for mock mode
        return true;
    }

    public override async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
    {
        LogDebug("Mock: TestConnectionAsync called");
        
        await Task.Delay(50, cancellationToken);

        // Always succeed in mock mode
        return true;
    }

    public override async Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
    {
        LogDebug("Mock: GetServerInfoAsync called");
        
        await Task.Delay(50, cancellationToken);        return new AuthServerInfo
        {
            TokenEndpoint = "https://mock-auth-server.example.com/token",
            AuthorizationEndpoint = "https://mock-auth-server.example.com/authorize",
            RevocationEndpoint = "https://mock-auth-server.example.com/revoke",
            IntrospectionEndpoint = "https://mock-auth-server.example.com/introspect",
            GrantTypesSupported = new List<string> { "client_credentials", "authorization_code", "refresh_token" },
            ScopesSupported = new List<string> { "read", "write", "api" }
        };
    }

    public override void ClearTokens()
    {
        LogDebug("Mock: ClearTokens called");
        
        lock (_tokenLock)
        {
            _currentToken = null;
        }
    }

    public override AuthToken? CurrentToken
    {
        get
        {
            lock (_tokenLock)
            {
                return _currentToken;
            }
        }
    }

    public override bool IsAuthenticated => IsTokenValid();
}
