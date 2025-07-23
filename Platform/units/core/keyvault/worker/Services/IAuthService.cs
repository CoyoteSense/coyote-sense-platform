using System.Threading.Tasks;

namespace Coyote.Units.KeyVault.Services
{
    /// <summary>
    /// Authentication service interface
    /// </summary>
    public interface IAuthService
    {
        /// <summary>
        /// Initialize the authentication service
        /// </summary>
        Task InitializeAsync();

        /// <summary>
        /// Authenticate a unit and issue a bearer token
        /// </summary>
        /// <param name="credentials">Unit credentials</param>
        /// <returns>Bearer token</returns>
        Task<AuthToken> AuthenticateAsync(UnitCredentials credentials);

        /// <summary>
        /// Validate a bearer token
        /// </summary>
        /// <param name="token">Bearer token to validate</param>
        /// <returns>Validation result</returns>
        Task<AuthValidationResult> ValidateTokenAsync(string token);

        /// <summary>
        /// Revoke a bearer token
        /// </summary>
        /// <param name="token">Token to revoke</param>
        /// <returns>Success status</returns>
        Task<bool> RevokeTokenAsync(string token);

        /// <summary>
        /// Check if the service is healthy
        /// </summary>
        Task<bool> IsHealthyAsync();

        /// <summary>
        /// Get count of active tokens
        /// </summary>
        Task<int> GetActiveTokenCountAsync();
    }

    /// <summary>
    /// Unit credentials for authentication
    /// </summary>
    public class UnitCredentials
    {
        public string UnitId { get; set; } = string.Empty;
        public string UnitRole { get; set; } = string.Empty;
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
        public string? CertificateThumbprint { get; set; }
        public string? JwtToken { get; set; }
    }

    /// <summary>
    /// Authentication token
    /// </summary>
    public class AuthToken
    {
        public string Token { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public string UnitId { get; set; } = string.Empty;
        public string UnitRole { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty;
    }

    /// <summary>
    /// Token validation result
    /// </summary>
    public class AuthValidationResult
    {
        public bool IsValid { get; set; }
        public string? UnitId { get; set; }
        public string? UnitRole { get; set; }
        public string? Error { get; set; }
    }
} 