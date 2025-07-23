using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Coyote.Units.KeyVault.Services
{
    /// <summary>
    /// Mock implementation of authentication service for testing
    /// </summary>
    public class AuthService : IAuthService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;
        private readonly ConcurrentDictionary<string, AuthToken> _activeTokens;
        private readonly string _masterKey;

        public AuthService(IConfiguration configuration, ILogger<AuthService> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _activeTokens = new ConcurrentDictionary<string, AuthToken>();
            _masterKey = _configuration["MasterKey"] ?? "mock-master-key";
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing AuthService...");
            await Task.Delay(100); // Simulate initialization
            _logger.LogInformation("AuthService initialized successfully");
        }

        public async Task<AuthToken> AuthenticateAsync(UnitCredentials credentials)
        {
            _logger.LogInformation("Authenticating unit {UnitId} with role {Role}", 
                credentials.UnitId, credentials.UnitRole);

            // Simulate authentication delay
            await Task.Delay(50);

            // Generate a mock token
            var token = new AuthToken
            {
                Token = $"mock-token-{credentials.UnitId}-{Guid.NewGuid()}",
                ExpiresAt = DateTime.UtcNow.AddMinutes(15),
                UnitId = credentials.UnitId,
                UnitRole = credentials.UnitRole,
                Scope = $"mock-scope-{credentials.UnitRole}"
            };

            // Store the token
            _activeTokens[token.Token] = token;

            _logger.LogInformation("Authentication successful for unit {UnitId}", credentials.UnitId);
            return token;
        }

        public async Task<AuthValidationResult> ValidateTokenAsync(string token)
        {
            _logger.LogDebug("Validating token");

            await Task.Delay(10); // Simulate validation delay

            if (_activeTokens.TryGetValue(token, out var authToken))
            {
                if (authToken.ExpiresAt > DateTime.UtcNow)
                {
                    return new AuthValidationResult
                    {
                        IsValid = true,
                        UnitId = authToken.UnitId,
                        UnitRole = authToken.UnitRole
                    };
                }
                else
                {
                    // Remove expired token
                    _activeTokens.TryRemove(token, out _);
                    return new AuthValidationResult
                    {
                        IsValid = false,
                        Error = "Token expired"
                    };
                }
            }

            return new AuthValidationResult
            {
                IsValid = false,
                Error = "Invalid token"
            };
        }

        public async Task<bool> RevokeTokenAsync(string token)
        {
            _logger.LogInformation("Revoking token");

            await Task.Delay(10); // Simulate revocation delay

            return _activeTokens.TryRemove(token, out _);
        }

        public async Task<bool> IsHealthyAsync()
        {
            _logger.LogDebug("AuthService health check");
            await Task.Delay(1);
            return true;
        }

        public async Task<int> GetActiveTokenCountAsync()
        {
            await Task.Delay(1);
            return _activeTokens.Count;
        }
    }
} 