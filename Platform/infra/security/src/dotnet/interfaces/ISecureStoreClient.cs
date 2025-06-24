using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Secure store client interface for accessing secrets from KeyVault
/// Provides secure, authenticated access to encrypted secrets stored in the KeyVault service.
/// All operations require valid bearer tokens obtained through IAuthClient authentication.
/// </summary>
public interface ISecureStoreClient : IDisposable
{
    /// <summary>
    /// Retrieve a secret by path
    /// </summary>
    /// <param name="secretPath">Path to the secret (e.g., "db/password", "api/keys/stripe")</param>
    /// <param name="version">Optional version of the secret (defaults to latest)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Secret value or null if not found</returns>
    Task<SecretValue?> GetSecretAsync(string secretPath, string? version = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieve multiple secrets by paths
    /// </summary>
    /// <param name="secretPaths">Collection of secret paths to retrieve</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Dictionary of path -> secret value (missing secrets are excluded)</returns>
    Task<Dictionary<string, SecretValue>> GetSecretsAsync(IEnumerable<string> secretPaths, CancellationToken cancellationToken = default);

    /// <summary>
    /// Store or update a secret
    /// </summary>
    /// <param name="secretPath">Path where to store the secret</param>
    /// <param name="secretValue">Secret value to store</param>
    /// <param name="metadata">Optional metadata associated with the secret</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Version of the stored secret</returns>
    Task<string> SetSecretAsync(string secretPath, string secretValue, Dictionary<string, string>? metadata = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Delete a secret
    /// </summary>
    /// <param name="secretPath">Path to the secret to delete</param>
    /// <param name="version">Optional specific version to delete (defaults to all versions)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if deleted successfully</returns>
    Task<bool> DeleteSecretAsync(string secretPath, string? version = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// List available secret paths (with optional prefix filtering)
    /// </summary>
    /// <param name="pathPrefix">Optional prefix to filter results (e.g., "db/" for database secrets)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of available secret paths</returns>
    Task<List<string>> ListSecretsAsync(string? pathPrefix = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get secret metadata without retrieving the actual value
    /// </summary>
    /// <param name="secretPath">Path to the secret</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Secret metadata or null if not found</returns>
    Task<SecretMetadata?> GetSecretMetadataAsync(string secretPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Test connection to the KeyVault service
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if connection is successful</returns>
    Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Get health status of the KeyVault service
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>KeyVault health status</returns>
    Task<KeyVaultHealthStatus?> GetHealthStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Current authentication status
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// KeyVault server URL
    /// </summary>
    string ServerUrl { get; }
}

/// <summary>
/// Represents a secret value retrieved from the secure store
/// </summary>
public class SecretValue
{
    public string Path { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
    
    /// <summary>
    /// Securely clear the secret value from memory
    /// </summary>
    public void Clear()
    {
        if (!string.IsNullOrEmpty(Value))
        {
            // Overwrite the string memory (best effort)
            Value = new string('\0', Value.Length);
            Value = string.Empty;
        }
    }
}

/// <summary>
/// Metadata information about a secret without the actual value
/// </summary>
public class SecretMetadata
{
    public string Path { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
    public List<string> AvailableVersions { get; set; } = new();
}

/// <summary>
/// Health status of the KeyVault service
/// </summary>
public class KeyVaultHealthStatus
{
    public bool IsHealthy { get; set; }
    public string Status { get; set; } = string.Empty;
    public Dictionary<string, object> Details { get; set; } = new();
    public DateTime CheckedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Exception thrown when secure store operations fail
/// </summary>
public class SecureStoreException : Exception
{
    public string? ErrorCode { get; }
    public int? HttpStatusCode { get; }

    public SecureStoreException(string message) : base(message) { }
    public SecureStoreException(string message, Exception innerException) : base(message, innerException) { }
    public SecureStoreException(string message, string? errorCode, int? httpStatusCode = null) : base(message)
    {
        ErrorCode = errorCode;
        HttpStatusCode = httpStatusCode;
    }
    public SecureStoreException(string errorCode, string message, Exception innerException) : base(message, innerException)
    {
        ErrorCode = errorCode;
        HttpStatusCode = null;
    }
}
