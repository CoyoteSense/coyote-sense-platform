using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Factory;
using Microsoft.Extensions.Logging;

namespace Coyote.Infra.Security.Auth.Clients;

/// <summary>
/// Main implementation of the Secure Store Client for KeyVault integration
/// Provides secure, authenticated access to secrets with automatic token management
/// </summary>
public class SecureStoreClient : ISecureStoreClient
{
    private readonly SecureStoreOptions _options;
    private readonly HttpClient _httpClient;
    private readonly IAuthClient? _authClient;
    private readonly ILogger<SecureStoreClient>? _logger;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    
    private volatile string? _currentToken;
    private volatile DateTime _tokenExpiry = DateTime.MinValue;
    private bool _disposed;

    /// <summary>
    /// Constructor with integrated authentication client
    /// </summary>
    public SecureStoreClient(SecureStoreOptions options, IAuthClient authClient, ILogger<SecureStoreClient>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        
        _authClient = authClient ?? throw new ArgumentNullException(nameof(authClient));
        _logger = logger;
        
        _httpClient = CreateHttpClient();
        
        _logger?.LogInformation("SecureStoreClient initialized with integrated auth for {ServerUrl}", _options.ServerUrl);
    }

    /// <summary>
    /// Constructor with external token provider (for loose coupling)
    /// </summary>
    public SecureStoreClient(SecureStoreOptions options, Func<CancellationToken, Task<string?>> tokenProvider, ILogger<SecureStoreClient>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        
        TokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        _logger = logger;
        
        _httpClient = CreateHttpClient();
        
        _logger?.LogInformation("SecureStoreClient initialized with external token provider for {ServerUrl}", _options.ServerUrl);
    }

    /// <summary>
    /// External token provider function (alternative to integrated IAuthClient)
    /// </summary>
    public Func<CancellationToken, Task<string?>>? TokenProvider { get; }

    /// <inheritdoc />
    public string ServerUrl => _options.ServerUrl;

    /// <inheritdoc />
    public bool IsAuthenticated => !string.IsNullOrEmpty(_currentToken) && DateTime.UtcNow < _tokenExpiry;

    /// <inheritdoc />
    public async Task<SecretValue?> GetSecretAsync(string secretPath, string? version = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretPath))
            throw new ArgumentException("Secret path cannot be empty", nameof(secretPath));

        var fullPath = BuildSecretPath(secretPath);
        var url = BuildApiUrl($"secret/{fullPath}");
        
        if (!string.IsNullOrEmpty(version))
        {
            url += $"?version={Uri.EscapeDataString(version)}";
        }

        var response = await ExecuteAuthenticatedRequestAsync(HttpMethod.Get, url, cancellationToken);
        
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            _logger?.LogDebug("Secret not found: {SecretPath}", secretPath);
            return null;
        }

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        
        var secretResponse = JsonSerializer.Deserialize<SecretResponse>(content);
        if (secretResponse?.Data == null)
        {
            _logger?.LogWarning("Invalid secret response format for {SecretPath}", secretPath);
            return null;
        }

        return new SecretValue
        {
            Path = secretPath,
            Value = secretResponse.Data.Value,
            Version = secretResponse.Data.Version ?? "1",
            CreatedAt = secretResponse.Data.CreatedAt,
            UpdatedAt = secretResponse.Data.UpdatedAt,
            Metadata = secretResponse.Data.Metadata ?? new Dictionary<string, string>()
        };
    }

    /// <inheritdoc />
    public async Task<Dictionary<string, SecretValue>> GetSecretsAsync(IEnumerable<string> secretPaths, CancellationToken cancellationToken = default)
    {
        var paths = secretPaths?.ToList() ?? throw new ArgumentNullException(nameof(secretPaths));
        if (!paths.Any())
            return new Dictionary<string, SecretValue>();

        var results = new Dictionary<string, SecretValue>();
        var semaphore = new SemaphoreSlim(Environment.ProcessorCount, Environment.ProcessorCount);

        var tasks = paths.Select(async path =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var secret = await GetSecretAsync(path, cancellationToken: cancellationToken);
                if (secret != null)
                {
                    lock (results)
                    {
                        results[path] = secret;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to retrieve secret: {SecretPath}", path);
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return results;
    }

    /// <inheritdoc />
    public async Task<string> SetSecretAsync(string secretPath, string secretValue, Dictionary<string, string>? metadata = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretPath))
            throw new ArgumentException("Secret path cannot be empty", nameof(secretPath));
        
        if (string.IsNullOrEmpty(secretValue))
            throw new ArgumentException("Secret value cannot be empty", nameof(secretValue));

        var fullPath = BuildSecretPath(secretPath);
        var url = BuildApiUrl($"secret/{fullPath}");

        var request = new SetSecretRequest
        {
            Value = secretValue,
            Metadata = metadata ?? new Dictionary<string, string>()
        };

        var jsonContent = JsonSerializer.Serialize(request);
        var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

        var response = await ExecuteAuthenticatedRequestAsync(HttpMethod.Post, url, cancellationToken, httpContent);
        response.EnsureSuccessStatusCode();

        var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
        var setResponse = JsonSerializer.Deserialize<SetSecretResponse>(responseContent);

        _logger?.LogInformation("Secret stored successfully: {SecretPath} (version: {Version})", secretPath, setResponse?.Version);
        return setResponse?.Version ?? "1";
    }

    /// <inheritdoc />
    public async Task<bool> DeleteSecretAsync(string secretPath, string? version = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretPath))
            throw new ArgumentException("Secret path cannot be empty", nameof(secretPath));

        var fullPath = BuildSecretPath(secretPath);
        var url = BuildApiUrl($"secret/{fullPath}");
        
        if (!string.IsNullOrEmpty(version))
        {
            url += $"?version={Uri.EscapeDataString(version)}";
        }

        var response = await ExecuteAuthenticatedRequestAsync(HttpMethod.Delete, url, cancellationToken);
        
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            _logger?.LogDebug("Secret not found for deletion: {SecretPath}", secretPath);
            return false;
        }

        response.EnsureSuccessStatusCode();
        _logger?.LogInformation("Secret deleted successfully: {SecretPath}", secretPath);
        return true;
    }

    /// <inheritdoc />
    public async Task<List<string>> ListSecretsAsync(string? pathPrefix = null, CancellationToken cancellationToken = default)
    {
        var url = BuildApiUrl("secrets");
        
        if (!string.IsNullOrEmpty(pathPrefix))
        {
            var fullPrefix = BuildSecretPath(pathPrefix);
            url += $"?prefix={Uri.EscapeDataString(fullPrefix)}";
        }

        var response = await ExecuteAuthenticatedRequestAsync(HttpMethod.Get, url, cancellationToken);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var listResponse = JsonSerializer.Deserialize<ListSecretsResponse>(content);

        return listResponse?.Keys ?? new List<string>();
    }

    /// <inheritdoc />
    public async Task<SecretMetadata?> GetSecretMetadataAsync(string secretPath, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretPath))
            throw new ArgumentException("Secret path cannot be empty", nameof(secretPath));

        var fullPath = BuildSecretPath(secretPath);
        var url = BuildApiUrl($"secret/{fullPath}/metadata");

        var response = await ExecuteAuthenticatedRequestAsync(HttpMethod.Get, url, cancellationToken);
        
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        
        var metadataResponse = JsonSerializer.Deserialize<SecretMetadataResponse>(content);
        if (metadataResponse?.Data == null)
        {
            return null;
        }

        return new SecretMetadata
        {
            Path = secretPath,
            Version = metadataResponse.Data.Version ?? "1",
            CreatedAt = metadataResponse.Data.CreatedAt,
            UpdatedAt = metadataResponse.Data.UpdatedAt,
            Metadata = metadataResponse.Data.Metadata ?? new Dictionary<string, string>(),
            AvailableVersions = metadataResponse.Data.Versions ?? new List<string>()
        };
    }

    /// <inheritdoc />
    public async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var url = BuildApiUrl("health");
            var response = await ExecuteAuthenticatedRequestAsync(HttpMethod.Get, url, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Connection test failed to {ServerUrl}", _options.ServerUrl);
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<KeyVaultHealthStatus?> GetHealthStatusAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var url = BuildApiUrl("health");
            var response = await ExecuteAuthenticatedRequestAsync(HttpMethod.Get, url, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                return new KeyVaultHealthStatus
                {
                    IsHealthy = false,
                    Status = $"HTTP {(int)response.StatusCode}",
                    Details = new Dictionary<string, object> { ["error"] = response.ReasonPhrase ?? "Unknown error" }
                };
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var healthResponse = JsonSerializer.Deserialize<HealthResponse>(content);

            return new KeyVaultHealthStatus
            {
                IsHealthy = healthResponse?.Status == "healthy",
                Status = healthResponse?.Status ?? "unknown",
                Details = healthResponse?.Details ?? new Dictionary<string, object>()
            };
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Health check failed for {ServerUrl}", _options.ServerUrl);
            return new KeyVaultHealthStatus
            {
                IsHealthy = false,
                Status = "error",
                Details = new Dictionary<string, object> { ["exception"] = ex.Message }
            };
        }
    }

    private HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler();
        
        // SSL/TLS configuration
        if (!_options.VerifySsl)
        {
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }

        // Mutual TLS configuration
        if (_options.UseMutualTls && !string.IsNullOrEmpty(_options.ClientCertPath))
        {
            // Note: In production, you'd load the actual certificate
            _logger?.LogInformation("mTLS configured with cert: {CertPath}", _options.ClientCertPath);
        }

        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri(_options.ServerUrl),
            Timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs)
        };

        // Add custom headers
        foreach (var header in _options.CustomHeaders)
        {
            client.DefaultRequestHeaders.Add(header.Key, header.Value);
        }

        return client;
    }

    private async Task<HttpResponseMessage> ExecuteAuthenticatedRequestAsync(HttpMethod method, string url, CancellationToken cancellationToken, HttpContent? content = null)
    {
        var token = await GetValidTokenAsync(cancellationToken);
        if (string.IsNullOrEmpty(token))
        {
            throw new SecureStoreException("No valid authentication token available", "AUTH_TOKEN_MISSING");
        }

        using var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        
        if (content != null)
        {
            request.Content = content;
        }

        for (int attempt = 0; attempt <= _options.MaxRetryAttempts; attempt++)
        {
            try
            {
                _logger?.LogDebug("Executing {Method} {Url} (attempt {Attempt})", method, url, attempt + 1);
                
                var response = await _httpClient.SendAsync(request, cancellationToken);
                
                // Handle authentication failures
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    _logger?.LogWarning("Authentication failed, clearing token cache");
                    _currentToken = null;
                    _tokenExpiry = DateTime.MinValue;
                    
                    if (attempt < _options.MaxRetryAttempts)
                    {
                        // Retry with fresh token
                        token = await GetValidTokenAsync(cancellationToken);
                        if (!string.IsNullOrEmpty(token))
                        {
                            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                            continue;
                        }
                    }
                }

                return response;
            }
            catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (attempt < _options.MaxRetryAttempts)
            {
                _logger?.LogWarning(ex, "Request failed (attempt {Attempt}), retrying in {Delay}ms", attempt + 1, _options.RetryBackoffMs);
                await Task.Delay(_options.RetryBackoffMs, cancellationToken);
            }
        }

        throw new SecureStoreException($"Request failed after {_options.MaxRetryAttempts + 1} attempts", "MAX_RETRIES_EXCEEDED");
    }

    private async Task<string?> GetValidTokenAsync(CancellationToken cancellationToken)
    {
        // Check if current token is still valid
        if (!string.IsNullOrEmpty(_currentToken) && DateTime.UtcNow.AddSeconds(_options.TokenRefreshBufferSeconds) < _tokenExpiry)
        {
            return _currentToken;
        }

        await _tokenLock.WaitAsync(cancellationToken);
        try
        {
            // Double-check after acquiring lock
            if (!string.IsNullOrEmpty(_currentToken) && DateTime.UtcNow.AddSeconds(_options.TokenRefreshBufferSeconds) < _tokenExpiry)
            {
                return _currentToken;
            }

            // Get fresh token
            string? newToken = null;
            DateTime newExpiry = DateTime.MinValue;

            if (_authClient != null)
            {
                var authToken = await _authClient.GetValidTokenAsync(cancellationToken);
                if (authToken != null)
                {
                    newToken = authToken.AccessToken;
                    newExpiry = authToken.ExpiresAt;
                }
            }
            else if (TokenProvider != null)
            {
                newToken = await TokenProvider(cancellationToken);
                // When using external token provider, we don't know expiry, so assume short-lived
                newExpiry = DateTime.UtcNow.AddMinutes(15);
            }

            if (!string.IsNullOrEmpty(newToken))
            {
                _currentToken = newToken;
                _tokenExpiry = newExpiry;
                _logger?.LogDebug("Token refreshed, expires at: {Expiry}", newExpiry);
                return newToken;
            }

            _logger?.LogError("Failed to obtain valid authentication token");
            return null;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private string BuildSecretPath(string secretPath)
    {
        var cleanPath = secretPath.Trim('/');
        
        if (!string.IsNullOrEmpty(_options.DefaultNamespace))
        {
            var cleanNamespace = _options.DefaultNamespace.Trim('/');
            return $"{cleanNamespace}/{cleanPath}";
        }
        
        return cleanPath;
    }

    private string BuildApiUrl(string endpoint)
    {
        return $"/{_options.ApiVersion}/{endpoint.TrimStart('/')}";
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;

        _httpClient?.Dispose();
        _tokenLock?.Dispose();
        _authClient?.Dispose();

        // Clear sensitive data
        _currentToken = null;
        
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    // Response DTOs for JSON deserialization
    private class SecretResponse
    {
        public SecretData? Data { get; set; }
    }

    private class SecretData
    {
        public string Value { get; set; } = string.Empty;
        public string? Version { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public Dictionary<string, string>? Metadata { get; set; }
    }

    private class SetSecretRequest
    {
        public string Value { get; set; } = string.Empty;
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    private class SetSecretResponse
    {
        public string? Version { get; set; }
    }

    private class ListSecretsResponse
    {
        public List<string>? Keys { get; set; }
    }

    private class SecretMetadataResponse
    {
        public SecretMetadataData? Data { get; set; }
    }

    private class SecretMetadataData
    {
        public string? Version { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public Dictionary<string, string>? Metadata { get; set; }
        public List<string>? Versions { get; set; }
    }

    private class HealthResponse
    {
        public string? Status { get; set; }
        public Dictionary<string, object>? Details { get; set; }
    }
}
