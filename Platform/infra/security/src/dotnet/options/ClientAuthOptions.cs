using System;
using System.Collections.Generic;

namespace Coyote.Infra.Security.Auth.Options;

/// <summary>
/// Options for client credentials authentication flow
/// </summary>
public class ClientCredentialsOptions
{
    /// <summary>
    /// OAuth2/OIDC server URL
    /// </summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>
    /// Client identifier
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Client secret for authentication
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Requested scopes for the access token
    /// </summary>
    public List<string> Scopes { get; set; } = new();

    /// <summary>
    /// Default scopes to use if none are specified
    /// </summary>
    public List<string> DefaultScopes { get; set; } = new();

    /// <summary>
    /// Token endpoint path (defaults to "/oauth2/token")
    /// </summary>
    public string TokenEndpoint { get; set; } = "/oauth2/token";

    /// <summary>
    /// Request timeout in milliseconds
    /// </summary>
    public int TimeoutMs { get; set; } = 30000;

    /// <summary>
    /// Whether to automatically refresh tokens before expiry
    /// </summary>
    public bool AutoRefresh { get; set; } = true;

    /// <summary>
    /// Token refresh buffer time in seconds (refresh this many seconds before expiry)
    /// </summary>
    public int RefreshBufferSeconds { get; set; } = 300;

    /// <summary>
    /// Convert to AuthClientConfig for factory use
    /// </summary>
    public AuthClientConfig ToAuthClientConfig()
    {
        return new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = ServerUrl,
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            DefaultScopes = Scopes,
            AutoRefresh = AutoRefresh,
            TimeoutMs = TimeoutMs
        };
    }

    /// <summary>
    /// Validate the configuration
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ServerUrl))
            throw new ArgumentException("ServerUrl is required", nameof(ServerUrl));
        
        if (string.IsNullOrWhiteSpace(ClientId))
            throw new ArgumentException("ClientId is required", nameof(ClientId));
        
        if (string.IsNullOrWhiteSpace(ClientSecret))
            throw new ArgumentException("ClientSecret is required", nameof(ClientSecret));
    }
}

/// <summary>
/// Options for JWT Bearer authentication flow
/// </summary>
public class JwtBearerOptions
{
    /// <summary>
    /// OAuth2/OIDC server URL
    /// </summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>
    /// Client identifier
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// JWT assertion for authentication
    /// </summary>
    public string Assertion { get; set; } = string.Empty;

    /// <summary>
    /// Requested scopes for the access token
    /// </summary>
    public List<string> Scopes { get; set; } = new();

    /// <summary>
    /// Token endpoint path (defaults to "/oauth2/token")
    /// </summary>
    public string TokenEndpoint { get; set; } = "/oauth2/token";

    /// <summary>
    /// Request timeout in milliseconds
    /// </summary>
    public int TimeoutMs { get; set; } = 30000;

    /// <summary>
    /// Whether to automatically refresh tokens before expiry
    /// </summary>
    public bool AutoRefresh { get; set; } = true;

    /// <summary>
    /// Token refresh buffer time in seconds
    /// </summary>
    public int RefreshBufferSeconds { get; set; } = 300;

    /// <summary>
    /// Path to JWT signing key file
    /// </summary>
    public string JwtSigningKeyPath { get; set; } = string.Empty;

    /// <summary>
    /// JWT issuer identifier
    /// </summary>
    public string JwtIssuer { get; set; } = string.Empty;

    /// <summary>
    /// JWT audience identifier
    /// </summary>
    public string JwtAudience { get; set; } = string.Empty;

    /// <summary>
    /// Default scopes to use if none are specified
    /// </summary>
    public List<string> DefaultScopes { get; set; } = new();

    /// <summary>
    /// Convert to AuthClientConfig for factory use
    /// </summary>
    public AuthClientConfig ToAuthClientConfig()
    {
        return new AuthClientConfig
        {
            AuthMode = AuthMode.JwtBearer,
            ServerUrl = ServerUrl,
            ClientId = ClientId,
            JwtIssuer = Assertion, // Use assertion as issuer for now
            DefaultScopes = Scopes,
            AutoRefresh = AutoRefresh,
            TimeoutMs = TimeoutMs
        };
    }

    /// <summary>
    /// Validate the configuration
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ServerUrl))
            throw new ArgumentException("ServerUrl is required", nameof(ServerUrl));
        
        if (string.IsNullOrWhiteSpace(ClientId))
            throw new ArgumentException("ClientId is required", nameof(ClientId));
        
        if (string.IsNullOrWhiteSpace(Assertion))
            throw new ArgumentException("Assertion is required", nameof(Assertion));
    }
}
