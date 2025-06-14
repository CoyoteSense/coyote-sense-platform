using System;
using System.Collections.Generic;

namespace Coyote.Infra.Security.Auth.Options;

/// <summary>
/// Configuration options for the Secure Store Client
/// </summary>
public class SecureStoreOptions
{
    /// <summary>
    /// KeyVault server URL (e.g., "https://keyvault.coyotesense.io")
    /// </summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>
    /// API version to use (defaults to "v1")
    /// </summary>
    public string ApiVersion { get; set; } = "v1";

    /// <summary>
    /// Timeout for HTTP requests in milliseconds
    /// </summary>
    public int TimeoutMs { get; set; } = 30000;

    /// <summary>
    /// Maximum number of retry attempts for failed requests
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Backoff delay between retry attempts in milliseconds
    /// </summary>
    public int RetryBackoffMs { get; set; } = 1000;

    /// <summary>
    /// Whether to verify SSL certificates
    /// </summary>
    public bool VerifySsl { get; set; } = true;

    /// <summary>
    /// Path to CA certificate for server verification
    /// </summary>
    public string? CaCertPath { get; set; }

    /// <summary>
    /// Whether to use mutual TLS (mTLS)
    /// </summary>
    public bool UseMutualTls { get; set; } = false;

    /// <summary>
    /// Client certificate path for mTLS
    /// </summary>
    public string? ClientCertPath { get; set; }

    /// <summary>
    /// Client private key path for mTLS
    /// </summary>
    public string? ClientKeyPath { get; set; }

    /// <summary>
    /// Default namespace/prefix for secrets (optional)
    /// </summary>
    public string? DefaultNamespace { get; set; }

    /// <summary>
    /// Whether to enable automatic token refresh
    /// </summary>
    public bool AutoRefreshToken { get; set; } = true;

    /// <summary>
    /// Buffer time in seconds before token expiry to trigger refresh
    /// </summary>
    public int TokenRefreshBufferSeconds { get; set; } = 300; // 5 minutes

    /// <summary>
    /// Custom headers to include in all requests
    /// </summary>
    public Dictionary<string, string> CustomHeaders { get; set; } = new();

    /// <summary>
    /// Whether to enable request/response logging
    /// </summary>
    public bool EnableLogging { get; set; } = true;

    /// <summary>
    /// Whether to enable performance metrics collection
    /// </summary>
    public bool EnableMetrics { get; set; } = true;

    /// <summary>
    /// Validate the configuration options
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ServerUrl))
            throw new ArgumentException("ServerUrl is required", nameof(ServerUrl));

        if (!Uri.TryCreate(ServerUrl, UriKind.Absolute, out var uri) || 
            (uri.Scheme != "https" && uri.Scheme != "http"))
            throw new ArgumentException("ServerUrl must be a valid HTTP or HTTPS URL", nameof(ServerUrl));

        if (TimeoutMs <= 0)
            throw new ArgumentException("TimeoutMs must be positive", nameof(TimeoutMs));

        if (MaxRetryAttempts < 0)
            throw new ArgumentException("MaxRetryAttempts cannot be negative", nameof(MaxRetryAttempts));

        if (RetryBackoffMs < 0)
            throw new ArgumentException("RetryBackoffMs cannot be negative", nameof(RetryBackoffMs));

        if (TokenRefreshBufferSeconds < 0)
            throw new ArgumentException("TokenRefreshBufferSeconds cannot be negative", nameof(TokenRefreshBufferSeconds));

        if (UseMutualTls)
        {
            if (string.IsNullOrWhiteSpace(ClientCertPath))
                throw new ArgumentException("ClientCertPath is required when UseMutualTls is true", nameof(ClientCertPath));
            
            if (string.IsNullOrWhiteSpace(ClientKeyPath))
                throw new ArgumentException("ClientKeyPath is required when UseMutualTls is true", nameof(ClientKeyPath));
        }
    }
}

/// <summary>
/// Authentication integration options for Secure Store Client
/// </summary>
public class SecureStoreAuthOptions : SecureStoreOptions
{
    /// <summary>
    /// Whether to use integrated authentication with IAuthClient
    /// </summary>
    public bool UseIntegratedAuth { get; set; } = true;

    /// <summary>
    /// Required scopes for KeyVault access
    /// </summary>
    public List<string> RequiredScopes { get; set; } = new() { "keyvault.read" };

    /// <summary>
    /// Whether to automatically refresh authentication tokens
    /// </summary>
    public bool AutoRefreshAuth { get; set; } = true;

    /// <summary>
    /// Authentication client configuration (when not providing existing IAuthClient)
    /// </summary>
    public AuthClientConfig? AuthClientConfig { get; set; }
}
