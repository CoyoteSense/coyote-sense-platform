using System.Collections.Generic;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Authentication client configuration options following CoyoteSense platform patterns
/// </summary>
public class AuthClientOptions
{
    /// <summary>
    /// Authentication mode to use
    /// </summary>
    public AuthMode Mode { get; set; } = AuthMode.ClientCredentials;

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
    public string TokenEndpoint { get; set; } = "/oauth/token";

    /// <summary>
    /// Full token URL (combines ServerUrl + TokenEndpoint)
    /// </summary>
    public string TokenUrl => string.IsNullOrEmpty(ServerUrl) ? TokenEndpoint : $"{ServerUrl.TrimEnd('/')}{TokenEndpoint}";

    /// <summary>
    /// OAuth2 authorization endpoint URL
    /// </summary>
    public string AuthorizeEndpoint { get; set; } = "/oauth/authorize";

    /// <summary>
    /// Full authorization URL (combines ServerUrl + AuthorizeEndpoint)
    /// </summary>
    public string AuthorizationUrl => string.IsNullOrEmpty(ServerUrl) ? AuthorizeEndpoint : $"{ServerUrl.TrimEnd('/')}{AuthorizeEndpoint}";

    /// <summary>
    /// OAuth2 token revocation endpoint URL
    /// </summary>
    public string RevocationEndpoint { get; set; } = "/oauth/revoke";

    /// <summary>
    /// Full revocation URL (combines ServerUrl + RevocationEndpoint)
    /// </summary>
    public string RevocationUrl => string.IsNullOrEmpty(ServerUrl) ? RevocationEndpoint : $"{ServerUrl.TrimEnd('/')}{RevocationEndpoint}";

    /// <summary>
    /// OAuth2 token introspection endpoint URL
    /// </summary>
    public string IntrospectionEndpoint { get; set; } = "/oauth/introspect";

    /// <summary>
    /// Full introspection URL (combines ServerUrl + IntrospectionEndpoint)
    /// </summary>
    public string IntrospectionUrl => string.IsNullOrEmpty(ServerUrl) ? IntrospectionEndpoint : $"{ServerUrl.TrimEnd('/')}{IntrospectionEndpoint}";

    /// <summary>
    /// OAuth2 discovery endpoint URL
    /// </summary>
    public string DiscoveryEndpoint { get; set; } = "/.well-known/openid_configuration";

    /// <summary>
    /// Full discovery URL (combines ServerUrl + DiscoveryEndpoint)
    /// </summary>
    public string DiscoveryUrl => string.IsNullOrEmpty(ServerUrl) ? DiscoveryEndpoint : $"{ServerUrl.TrimEnd('/')}{DiscoveryEndpoint}";

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
    /// Maximum number of retry attempts
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Whether to enable automatic token refresh
    /// </summary>
    public bool AutoRefresh { get; set; } = true;

    /// <summary>
    /// Token refresh threshold percentage (0.0 to 1.0)
    /// When the token has less than this percentage of time remaining, it will be refreshed
    /// </summary>
    public double RefreshThresholdPercentage { get; set; } = 0.1; // Refresh when 10% time remaining

    /// <summary>
    /// Whether to verify SSL/TLS peer certificates
    /// </summary>
    public bool VerifyPeer { get; set; } = true;

    /// <summary>
    /// Client certificate path for mTLS authentication
    /// </summary>
    public string? ClientCertPath { get; set; }

    /// <summary>
    /// Client certificate key path for mTLS authentication
    /// </summary>
    public string? ClientKeyPath { get; set; }

    /// <summary>
    /// CA certificate path for mTLS authentication
    /// </summary>
    public string? CaCertPath { get; set; }

    /// <summary>
    /// JWT signing key path for JWT Bearer flow
    /// </summary>
    public string? JwtSigningKeyPath { get; set; }

    /// <summary>
    /// JWT algorithm for JWT Bearer flow
    /// </summary>
    public string JwtAlgorithm { get; set; } = "RS256";

    /// <summary>
    /// JWT issuer for JWT Bearer flow
    /// </summary>
    public string? JwtIssuer { get; set; }

    /// <summary>
    /// JWT audience for JWT Bearer flow
    /// </summary>
    public string? JwtAudience { get; set; }

    /// <summary>
    /// Redirect URI for Authorization Code flow
    /// </summary>
    public string? RedirectUri { get; set; }

    /// <summary>
    /// Whether to use PKCE for Authorization Code flow
    /// </summary>
    public bool UsePkce { get; set; } = true;

    /// <summary>
    /// User agent string for HTTP requests
    /// </summary>
    public string UserAgent { get; set; } = "CoyoteAuth/1.0";

    /// <summary>
    /// Additional HTTP headers to include in requests
    /// </summary>
    public Dictionary<string, string> AdditionalHeaders { get; set; } = new();

    /// <summary>
    /// Whether to enable debug logging
    /// </summary>
    public bool EnableDebugLogging { get; set; } = false;

    /// <summary>
    /// Validate the configuration
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ServerUrl))
            throw new ArgumentException("ServerUrl is required", nameof(ServerUrl));

        if (string.IsNullOrWhiteSpace(ClientId))
            throw new ArgumentException("ClientId is required", nameof(ClientId));

        if (Mode == AuthMode.ClientCredentials && string.IsNullOrWhiteSpace(ClientSecret))
            throw new ArgumentException("ClientSecret is required for Client Credentials mode", nameof(ClientSecret));

        if (Mode == AuthMode.ClientCredentialsMtls)
        {
            if (string.IsNullOrWhiteSpace(ClientCertPath))
                throw new ArgumentException("ClientCertPath is required for mTLS mode", nameof(ClientCertPath));
            if (string.IsNullOrWhiteSpace(ClientKeyPath))
                throw new ArgumentException("ClientKeyPath is required for mTLS mode", nameof(ClientKeyPath));
        }

        if (Mode == AuthMode.JwtBearer)
        {
            if (string.IsNullOrWhiteSpace(JwtSigningKeyPath))
                throw new ArgumentException("JwtSigningKeyPath is required for JWT Bearer mode", nameof(JwtSigningKeyPath));
            if (string.IsNullOrWhiteSpace(JwtIssuer))
                throw new ArgumentException("JwtIssuer is required for JWT Bearer mode", nameof(JwtIssuer));
            if (string.IsNullOrWhiteSpace(JwtAudience))
                throw new ArgumentException("JwtAudience is required for JWT Bearer mode", nameof(JwtAudience));
        }

        if (Mode == AuthMode.AuthorizationCode || Mode == AuthMode.AuthorizationCodePkce)
        {
            if (string.IsNullOrWhiteSpace(RedirectUri))
                throw new ArgumentException("RedirectUri is required for Authorization Code mode", nameof(RedirectUri));
        }
    }
}
