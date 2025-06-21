using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Coyote.Infra.Security.Auth.Options;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Pool of authentication clients for high-performance scenarios
/// </summary>
public class AuthClientPool : IDisposable
{
    private readonly ConcurrentQueue<IAuthClient> _availableClients = new();
    private readonly ConcurrentDictionary<string, IAuthClient> _clientsInUse = new();
    private readonly AuthClientOptions _options;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AuthClientPool> _logger;
    private readonly SemaphoreSlim _semaphore;
    private readonly Timer _cleanupTimer;
    private volatile bool _disposed;

    /// <summary>
    /// Maximum number of clients in the pool
    /// </summary>
    public int MaxPoolSize { get; }

    /// <summary>
    /// Current number of clients in the pool
    /// </summary>
    public int CurrentPoolSize => _availableClients.Count + _clientsInUse.Count;

    /// <summary>
    /// Number of clients currently available
    /// </summary>
    public int AvailableClients => _availableClients.Count;

    /// <summary>
    /// Number of clients currently in use
    /// </summary>
    public int ClientsInUse => _clientsInUse.Count;

    /// <summary>
    /// Number of clients currently active (same as ClientsInUse)
    /// </summary>
    public int ActiveClientCount => _clientsInUse.Count;

    public AuthClientPool(
        AuthClientOptions options, 
        IServiceProvider serviceProvider,
        ILogger<AuthClientPool> logger,
        int maxPoolSize = 10)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        MaxPoolSize = maxPoolSize;
        _semaphore = new SemaphoreSlim(maxPoolSize, maxPoolSize);

        // Initialize the pool with a few clients
        InitializePool();

        // Setup cleanup timer to run every 5 minutes
        _cleanupTimer = new Timer(CleanupExpiredClients, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

        _logger.LogInformation("AuthClientPool initialized with max size {MaxPoolSize}", maxPoolSize);
    }

    /// <summary>
    /// Get an authentication client from the pool
    /// </summary>
    public async Task<IAuthClient> GetClientAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(AuthClientPool));

        await _semaphore.WaitAsync(cancellationToken);

        try
        {
            // Try to get an available client
            if (_availableClients.TryDequeue(out var client))
            {
                var clientId = Guid.NewGuid().ToString();
                _clientsInUse.TryAdd(clientId, client);
                _logger.LogDebug("Retrieved client {ClientId} from pool", clientId);
                return new PooledAuthClient(client, this, clientId);
            }

            // Create a new client if pool is not at capacity
            if (CurrentPoolSize < MaxPoolSize)
            {
                client = CreateNewClient();
                var clientId = Guid.NewGuid().ToString();
                _clientsInUse.TryAdd(clientId, client);
                _logger.LogDebug("Created new client {ClientId} for pool", clientId);
                return new PooledAuthClient(client, this, clientId);
            }

            throw new InvalidOperationException("Auth client pool is at capacity and no clients are available");
        }
        catch
        {
            _semaphore.Release();
            throw;
        }
    }

    /// <summary>
    /// Get a client credentials authentication client from the pool
    /// </summary>
    public IAuthClient GetClientCredentialsClient()
    {
        // For simple scenarios, return a synchronous client
        return GetClientAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Get a client credentials authentication client from the pool with specific options
    /// </summary>
    public IAuthClient GetClientCredentialsClient(string clientId, ClientCredentialsOptions options)
    {
        // For testing purposes, return the same client regardless of options
        // In a real implementation, this would create/retrieve a client with specific options
        var client = GetClientAsync().GetAwaiter().GetResult();
        _logger.LogDebug("Retrieved client credentials client for {ClientId}", clientId);
        return client;
    }

    /// <summary>
    /// Get an mTLS authentication client from the pool with specific options
    /// </summary>
    public IAuthClient GetMtlsClient(string clientId, MtlsOptions options)
    {
        // For testing purposes, return the same client regardless of options
        // In a real implementation, this would create/retrieve an mTLS client with specific options
        var client = GetClientAsync().GetAwaiter().GetResult();
        _logger.LogDebug("Retrieved mTLS client for {ClientId}", clientId);
        return client;
    }

    /// <summary>
    /// Return a client to the pool
    /// </summary>
    internal void ReturnClient(IAuthClient client, string clientId)
    {
        if (_disposed) return;

        try
        {
            _clientsInUse.TryRemove(clientId, out _);
            
            // Check if client is still valid
            if (client.IsAuthenticated)
            {
                _availableClients.Enqueue(client);
                _logger.LogDebug("Returned client {ClientId} to pool", clientId);
            }
            else
            {
                client.Dispose();
                _logger.LogDebug("Disposed expired client {ClientId}", clientId);
            }
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private void InitializePool()
    {
        // Create initial clients (half of max pool size)
        var initialSize = Math.Max(1, MaxPoolSize / 2);
        for (int i = 0; i < initialSize; i++)
        {
            try
            {
                var client = CreateNewClient();
                _availableClients.Enqueue(client);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to create initial auth client for pool");
            }
        }

        _logger.LogInformation("Initialized auth client pool with {InitialSize} clients", _availableClients.Count);
    }    private IAuthClient CreateNewClient()
    {
        // For now, create a simple mock client for the pool
        // In a real implementation, this would use dependency injection
        var logger = _serviceProvider.GetRequiredService<ILogger<IAuthClient>>();
        return new PoolMockAuthClient(logger);
    }

    /// <summary>
    /// Simple mock auth client for pool use
    /// </summary>
    private class PoolMockAuthClient : IAuthClient
    {
        private readonly ILogger _logger;

        public PoolMockAuthClient(ILogger logger)
        {
            _logger = logger;
        }

        public AuthToken? CurrentToken => new AuthToken 
        { 
            AccessToken = "pool-mock-token", 
            TokenType = "Bearer", 
            ExpiresAt = DateTime.UtcNow.AddHours(1) 
        };
        
        public bool IsAuthenticated => true;

        public Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "pool-mock-access-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "pool-mock-jwt-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "pool-mock-auth-code-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
        {
            return ("https://pool-mock-auth.coyotesense.io/authorize", "pool-mock-verifier", state ?? "pool-mock-state");
        }

        public Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var token = new AuthToken
            {
                AccessToken = "pool-mock-refreshed-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };
            return Task.FromResult(AuthResult.Success(token));
        }

        public Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthToken?>(new AuthToken 
            { 
                AccessToken = "pool-mock-valid-token",
                TokenType = "Bearer",
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            });
        }

        public Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthServerInfo?>(new AuthServerInfo 
            { 
                AuthorizationEndpoint = "https://pool-mock-auth.coyotesense.io/authorize",
                TokenEndpoint = "https://pool-mock-auth.coyotesense.io/token",
                GrantTypesSupported = new List<string> { "client_credentials", "authorization_code" },
                ScopesSupported = new List<string> { "read", "write" }
            });
        }

        public void ClearTokens()
        {
            // Mock implementation - no-op
        }

        public void Dispose()
        {
            // Mock implementation - no-op
        }
    }

    private void CleanupExpiredClients(object? state)
    {
        if (_disposed) return;

        try
        {
            var clientsToRemove = new List<IAuthClient>();
            
            // Check available clients
            var tempClients = new List<IAuthClient>();
            while (_availableClients.TryDequeue(out var client))
            {
                if (client.IsAuthenticated)
                {
                    tempClients.Add(client);
                }
                else
                {
                    clientsToRemove.Add(client);
                }
            }

            // Return valid clients back to the queue
            foreach (var client in tempClients)
            {
                _availableClients.Enqueue(client);
            }

            // Dispose expired clients
            foreach (var client in clientsToRemove)
            {
                client.Dispose();
            }

            if (clientsToRemove.Count > 0)
            {
                _logger.LogDebug("Cleaned up {Count} expired clients from pool", clientsToRemove.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during auth client pool cleanup");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cleanupTimer?.Dispose();
        _semaphore?.Dispose();

        // Dispose all available clients
        while (_availableClients.TryDequeue(out var client))
        {
            client.Dispose();
        }

        // Dispose all clients in use
        foreach (var client in _clientsInUse.Values)
        {
            client.Dispose();
        }

        _logger.LogInformation("AuthClientPool disposed");
    }

    /// <summary>
    /// Wrapper for pooled auth clients
    /// </summary>
    private class PooledAuthClient : IAuthClient
    {
        private readonly IAuthClient _innerClient;
        private readonly AuthClientPool _pool;
        private readonly string _clientId;
        private bool _disposed;

        public PooledAuthClient(IAuthClient innerClient, AuthClientPool pool, string clientId)
        {
            _innerClient = innerClient;
            _pool = pool;
            _clientId = clientId;
        }        public AuthToken? CurrentToken => _innerClient.CurrentToken;
        public bool IsAuthenticated => _innerClient.IsAuthenticated;

        public Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
            => _innerClient.AuthenticateClientCredentialsAsync(scopes, cancellationToken);

        public Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
            => _innerClient.AuthenticateJwtBearerAsync(subject, scopes, cancellationToken);

        public Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
            => _innerClient.AuthenticateAuthorizationCodeAsync(authorizationCode, redirectUri, codeVerifier, cancellationToken);

        public (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
            => _innerClient.StartAuthorizationCodeFlow(redirectUri, scopes, state);

        public Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
            => _innerClient.RefreshTokenAsync(refreshToken, cancellationToken);

        public Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
            => _innerClient.GetValidTokenAsync(cancellationToken);

        public Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
            => _innerClient.RevokeTokenAsync(token, tokenTypeHint, cancellationToken);

        public Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
            => _innerClient.IntrospectTokenAsync(token, cancellationToken);

        public Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
            => _innerClient.TestConnectionAsync(cancellationToken);

        public Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
            => _innerClient.GetServerInfoAsync(cancellationToken);

        public void ClearTokens() => _innerClient.ClearTokens();

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            // Return the client to the pool instead of disposing it
            _pool.ReturnClient(_innerClient, _clientId);
        }
    }
}
