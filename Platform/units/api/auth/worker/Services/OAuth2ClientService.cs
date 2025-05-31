using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CoyoteSense.AuthService;

// OAuth2 Client representation
public class OAuth2Client
{
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> AllowedScopes { get; set; } = new();
    public List<string> AllowedGrantTypes { get; set; } = new();
    public RSA? PublicKey { get; set; }
    public X509Certificate2? ClientCertificate { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; } = true;

    public bool ValidateSecret(string? providedSecret)
    {
        if (string.IsNullOrEmpty(ClientSecret))
        {
            return false;
        }

        // In production, use secure comparison
        return BCrypt.Net.BCrypt.Verify(providedSecret, ClientSecret);
    }

    public bool IsValidRedirectUri(string redirectUri)
    {
        return RedirectUris.Contains(redirectUri, StringComparer.OrdinalIgnoreCase);
    }

    public bool IsGrantTypeAllowed(string grantType)
    {
        return AllowedGrantTypes.Contains(grantType, StringComparer.OrdinalIgnoreCase);
    }

    public bool IsScopeAllowed(string scope)
    {
        var requestedScopes = scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
        return requestedScopes.All(s => AllowedScopes.Contains(s, StringComparer.OrdinalIgnoreCase));
    }
}

// OAuth2 Client Service Interface
public interface IOAuth2ClientService
{
    Task<OAuth2Client?> GetClientAsync(string clientId);
    Task<bool> ValidateClientCertificateAsync(string clientId, X509Certificate2 certificate);
    Task<OAuth2Client> CreateClientAsync(OAuth2Client client);
    Task<bool> UpdateClientAsync(OAuth2Client client);
    Task<bool> DeleteClientAsync(string clientId);
    Task<List<OAuth2Client>> GetAllClientsAsync();
}

// In-Memory OAuth2 Client Service (for development/testing)
public class InMemoryOAuth2ClientService : IOAuth2ClientService
{
    private readonly Dictionary<string, OAuth2Client> _clients = new();
    private readonly ILogger<InMemoryOAuth2ClientService> _logger;

    public InMemoryOAuth2ClientService(ILogger<InMemoryOAuth2ClientService> logger)
    {
        _logger = logger;
        InitializeDefaultClients();
    }

    private void InitializeDefaultClients()
    {
        // Example clients for different scenarios
        
        // Trading Unit - Client Credentials
        _clients["trading-unit-001"] = new OAuth2Client
        {
            ClientId = "trading-unit-001",
            ClientSecret = BCrypt.Net.BCrypt.HashPassword("trading-secret-001"),
            AllowedGrantTypes = { "client_credentials" },
            AllowedScopes = { "keyvault.read", "keyvault.write", "orders.submit" },
            IsActive = true
        };

        // Analytics Unit - mTLS
        _clients["analytics-unit-002"] = new OAuth2Client
        {
            ClientId = "analytics-unit-002",
            AllowedGrantTypes = { "client_credentials" },
            AllowedScopes = { "keyvault.read", "metrics.write", "analytics.access" },
            IsActive = true
        };

        // Core Service - JWT Bearer
        _clients["core-keyvault-service"] = new OAuth2Client
        {
            ClientId = "core-keyvault-service",
            AllowedGrantTypes = { "urn:ietf:params:oauth:grant-type:jwt-bearer" },
            AllowedScopes = { "keyvault.admin", "system.admin" },
            IsActive = true
        };

        // Dashboard - Authorization Code + PKCE
        _clients["coyote-dashboard"] = new OAuth2Client
        {
            ClientId = "coyote-dashboard",
            AllowedGrantTypes = { "authorization_code", "refresh_token" },
            AllowedScopes = { "keyvault.read", "dashboard.access", "user.profile" },
            RedirectUris = { "https://dashboard.coyotesense.local/callback" },
            IsActive = true
        };

        // Batch Processor
        _clients["batch-processor-001"] = new OAuth2Client
        {
            ClientId = "batch-processor-001",
            ClientSecret = BCrypt.Net.BCrypt.HashPassword("batch-secret-001"),
            AllowedGrantTypes = { "client_credentials" },
            AllowedScopes = { "keyvault.read", "data.process" },
            IsActive = true
        };

        _logger.LogInformation("Initialized {Count} default OAuth2 clients", _clients.Count);
    }

    public Task<OAuth2Client?> GetClientAsync(string clientId)
    {
        _clients.TryGetValue(clientId, out var client);
        return Task.FromResult(client);
    }

    public Task<bool> ValidateClientCertificateAsync(string clientId, X509Certificate2 certificate)
    {
        // In production, this would validate against stored certificate or CA
        // For now, just check if the certificate subject contains the client ID
        var isValid = certificate.Subject.Contains(clientId, StringComparison.OrdinalIgnoreCase);
        _logger.LogInformation("Client certificate validation for {ClientId}: {IsValid}", clientId, isValid);
        return Task.FromResult(isValid);
    }

    public Task<OAuth2Client> CreateClientAsync(OAuth2Client client)
    {
        client.CreatedAt = DateTime.UtcNow;
        _clients[client.ClientId] = client;
        _logger.LogInformation("Created OAuth2 client: {ClientId}", client.ClientId);
        return Task.FromResult(client);
    }

    public Task<bool> UpdateClientAsync(OAuth2Client client)
    {
        if (_clients.ContainsKey(client.ClientId))
        {
            _clients[client.ClientId] = client;
            _logger.LogInformation("Updated OAuth2 client: {ClientId}", client.ClientId);
            return Task.FromResult(true);
        }
        return Task.FromResult(false);
    }

    public Task<bool> DeleteClientAsync(string clientId)
    {
        var removed = _clients.Remove(clientId);
        if (removed)
        {
            _logger.LogInformation("Deleted OAuth2 client: {ClientId}", clientId);
        }
        return Task.FromResult(removed);
    }

    public Task<List<OAuth2Client>> GetAllClientsAsync()
    {
        return Task.FromResult(_clients.Values.ToList());
    }
}
