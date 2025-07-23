using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Coyote.Units.KeyVault.Services
{
    /// <summary>
    /// Mock implementation of secret service for testing
    /// </summary>
    public class SecretService : ISecretService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<SecretService> _logger;
        private readonly ConcurrentDictionary<string, string> _secrets;
        private readonly string _masterKey;

        public SecretService(IConfiguration configuration, ILogger<SecretService> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _secrets = new ConcurrentDictionary<string, string>();
            _masterKey = _configuration["MasterKey"] ?? "mock-master-key";

            // Initialize with some mock secrets
            _secrets["database/password"] = "mock-db-password";
            _secrets["api/key"] = "mock-api-key";
            _secrets["redis/connection"] = "mock-redis-connection";
            _secrets["jwt/secret"] = "mock-jwt-secret";
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing SecretService...");
            await Task.Delay(100); // Simulate initialization
            _logger.LogInformation("SecretService initialized successfully");
        }

        public async Task<string> GetSecretAsync(string secretPath, string unitId)
        {
            _logger.LogInformation("Unit {UnitId} requesting secret {SecretPath}", unitId, secretPath);

            await Task.Delay(20); // Simulate retrieval delay

            if (_secrets.TryGetValue(secretPath, out var secret))
            {
                _logger.LogInformation("Secret {SecretPath} retrieved successfully for unit {UnitId}", 
                    secretPath, unitId);
                return secret;
            }

            _logger.LogWarning("Secret {SecretPath} not found for unit {UnitId}", secretPath, unitId);
            throw new KeyNotFoundException($"Secret not found: {secretPath}");
        }

        public async Task<bool> SetSecretAsync(string secretPath, string secretValue, string unitId)
        {
            _logger.LogInformation("Unit {UnitId} setting secret {SecretPath}", unitId, secretPath);

            await Task.Delay(30); // Simulate storage delay

            _secrets[secretPath] = secretValue;

            _logger.LogInformation("Secret {SecretPath} stored successfully by unit {UnitId}", 
                secretPath, unitId);
            return true;
        }

        public async Task<bool> DeleteSecretAsync(string secretPath, string unitId)
        {
            _logger.LogInformation("Unit {UnitId} deleting secret {SecretPath}", unitId, secretPath);

            await Task.Delay(20); // Simulate deletion delay

            var removed = _secrets.TryRemove(secretPath, out _);

            if (removed)
            {
                _logger.LogInformation("Secret {SecretPath} deleted successfully by unit {UnitId}", 
                    secretPath, unitId);
            }
            else
            {
                _logger.LogWarning("Secret {SecretPath} not found for deletion by unit {UnitId}", 
                    secretPath, unitId);
            }

            return removed;
        }

        public async Task<string[]> ListSecretsAsync(string unitId)
        {
            _logger.LogInformation("Unit {UnitId} listing secrets", unitId);

            await Task.Delay(10); // Simulate listing delay

            return _secrets.Keys.ToArray();
        }

        public async Task<bool> IsHealthyAsync()
        {
            _logger.LogDebug("SecretService health check");
            await Task.Delay(1);
            return true;
        }

        public async Task<int> GetSecretCountAsync()
        {
            await Task.Delay(1);
            return _secrets.Count;
        }
    }
} 