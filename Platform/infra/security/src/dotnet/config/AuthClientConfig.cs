using System;
using System.Collections.Generic;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Legacy authentication client configuration for backward compatibility
/// </summary>
public class AuthClientConfig
{
    /// <summary>
    /// Authentication server base URL
    /// </summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>
    /// Authentication server base URL (alias for ServerUrl)
    /// </summary>
    public string BaseUrl 
    { 
        get => ServerUrl; 
        set => ServerUrl = value; 
    }

    /// <summary>
    /// OAuth2 token endpoint URL
    /// </summary>
    public string TokenUrl { get; set; } = string.Empty;

    /// <summary>
    /// OAuth2 authorization endpoint URL
    /// </summary>
    public string AuthorizationUrl { get; set; } = string.Empty;

    /// <summary>
    /// Authentication client ID
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Authentication client secret (for confidential clients)
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Default scopes to request
    /// </summary>
    public List<string> DefaultScopes { get; set; } = new();

    /// <summary>
    /// Default timeout for authentication requests in milliseconds
    /// </summary>
    public int TimeoutMs { get; set; } = 30000;

    /// <summary>
    /// Whether to enable automatic token refresh
    /// </summary>
    public bool AutoRefresh { get; set; } = true;

    /// <summary>
    /// Token refresh buffer time in seconds
    /// </summary>
    public int RefreshBufferSeconds { get; set; } = 300; // 5 minutes default

    /// <summary>
    /// Redirect URI for authorization code flow
    /// </summary>
    public string? RedirectUri { get; set; }

    /// <summary>
    /// Authentication mode to use
    /// </summary>
    public AuthMode Mode { get; set; } = AuthMode.ClientCredentials;

    /// <summary>
    /// Authentication mode to use (alias for Mode)
    /// </summary>
    public AuthMode AuthMode 
    { 
        get => Mode; 
        set => Mode = value; 
    }

    /// <summary>
    /// Client certificate path for mTLS authentication
    /// </summary>
    public string? ClientCertPath { get; set; }

    /// <summary>
    /// Client private key path for mTLS authentication
    /// </summary>
    public string? ClientKeyPath { get; set; }

    /// <summary>
    /// JWT signing key path for JWT Bearer authentication
    /// </summary>
    public string? JwtSigningKeyPath { get; set; }

    /// <summary>
    /// JWT issuer for JWT Bearer authentication
    /// </summary>
    public string? JwtIssuer { get; set; }

    /// <summary>
    /// JWT audience for JWT Bearer authentication
    /// </summary>
    public string? JwtAudience { get; set; }

    /// <summary>
    /// Whether to enable debug logging
    /// </summary>
    public bool EnableDebugLogging { get; set; } = false;

    /// <summary>
    /// Additional HTTP headers to include in requests
    /// </summary>
    public Dictionary<string, string> AdditionalHeaders { get; set; } = new();

    /// <summary>
    /// Convert to modern AuthClientOptions
    /// </summary>
    public AuthClientOptions ToAuthClientOptions()
    {
        return new AuthClientOptions
        {
            Mode = Mode,
            ServerUrl = ServerUrl,
            TokenEndpoint = ExtractEndpoint(TokenUrl, "/oauth/token"),
            AuthorizeEndpoint = ExtractEndpoint(AuthorizationUrl, "/oauth/authorize"),
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            DefaultScopes = DefaultScopes,
            TimeoutMs = TimeoutMs,
            AutoRefresh = AutoRefresh,
            ClientCertPath = ClientCertPath,
            ClientKeyPath = ClientKeyPath,
            JwtSigningKeyPath = JwtSigningKeyPath,
            JwtIssuer = JwtIssuer,
            JwtAudience = JwtAudience,
            EnableDebugLogging = EnableDebugLogging,
            AdditionalHeaders = AdditionalHeaders
        };
    }

    private string ExtractEndpoint(string fullUrl, string defaultEndpoint)
    {
        if (string.IsNullOrEmpty(fullUrl) || string.IsNullOrEmpty(ServerUrl))
            return defaultEndpoint;

        if (fullUrl.StartsWith(ServerUrl))
            return fullUrl.Substring(ServerUrl.TrimEnd('/').Length);

        return fullUrl.StartsWith('/') ? fullUrl : defaultEndpoint;
    }

    /// <summary>
    /// Validates the configuration
    /// </summary>
    public bool IsValid()
    {
        if (string.IsNullOrEmpty(ServerUrl) || string.IsNullOrEmpty(ClientId))
            return false;

        // For mTLS mode, client secret is not required
        if (Mode == AuthMode.ClientCredentialsMtls)
            return !string.IsNullOrEmpty(ClientCertPath) && !string.IsNullOrEmpty(ClientKeyPath);

        // For other modes, check if client secret is required
        return RequiresClientSecret() ? !string.IsNullOrEmpty(ClientSecret) : true;
    }

    /// <summary>
    /// Determines if client secret is required for the current auth mode
    /// </summary>
    public bool RequiresClientSecret()
    {
        return Mode switch
        {
            AuthMode.ClientCredentialsMtls => false,
            AuthMode.JwtBearer => false,
            _ => true
        };
    }
}
