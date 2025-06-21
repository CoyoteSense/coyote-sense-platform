using System;
using System.Collections.Generic;

namespace Coyote.Infra.Security.Auth;

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
    /// KeyVault server base URL (alias for ServerUrl)
    /// </summary>
    public string BaseUrl 
    { 
        get => ServerUrl; 
        set => ServerUrl = value; 
    }

    /// <summary>
    /// API version to use (defaults to "v1")
    /// </summary>
    public string ApiVersion { get; set; } = "v1";

    /// <summary>
    /// Token refresh buffer time in seconds
    /// </summary>
    public int TokenRefreshBufferSeconds { get; set; } = 300; // 5 minutes default

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
    /// Authentication options for accessing the secure store
    /// </summary>
    public AuthClientOptions? AuthOptions { get; set; }

    /// <summary>
    /// Default headers to include with requests
    /// </summary>
    public Dictionary<string, string> DefaultHeaders { get; set; } = new();

    /// <summary>
    /// Whether to enable debug logging
    /// </summary>
    public bool EnableDebugLogging { get; set; } = false;

    /// <summary>
    /// Cache settings for secrets
    /// </summary>
    public SecretCacheOptions Cache { get; set; } = new();

    /// <summary>
    /// Validate the secure store configuration
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ServerUrl))
            throw new ArgumentException("ServerUrl is required", nameof(ServerUrl));

        if (string.IsNullOrWhiteSpace(ApiVersion))
            throw new ArgumentException("ApiVersion is required", nameof(ApiVersion));

        if (UseMutualTls)
        {
            if (string.IsNullOrWhiteSpace(ClientCertPath))
                throw new ArgumentException("ClientCertPath is required when UseMutualTls is true", nameof(ClientCertPath));
            if (string.IsNullOrWhiteSpace(ClientKeyPath))
                throw new ArgumentException("ClientKeyPath is required when UseMutualTls is true", nameof(ClientKeyPath));
        }

        AuthOptions?.Validate();
    }
}

/// <summary>
/// Cache options for secrets
/// </summary>
public class SecretCacheOptions
{
    /// <summary>
    /// Whether to enable caching
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Cache expiration time in minutes
    /// </summary>
    public int ExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Maximum number of cached secrets
    /// </summary>
    public int MaxSize { get; set; } = 1000;

    /// <summary>
    /// Whether to refresh cache entries before expiration
    /// </summary>
    public bool RefreshBeforeExpiry { get; set; } = true;

    /// <summary>
    /// How many minutes before expiry to refresh
    /// </summary>
    public int RefreshBufferMinutes { get; set; } = 5;
}
