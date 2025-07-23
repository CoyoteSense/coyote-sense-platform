using System.Threading.Tasks;

namespace Coyote.Units.KeyVault.Services
{
    /// <summary>
    /// Secret management service interface
    /// </summary>
    public interface ISecretService
    {
        /// <summary>
        /// Initialize the secret service
        /// </summary>
        Task InitializeAsync();

        /// <summary>
        /// Get a secret by path
        /// </summary>
        /// <param name="secretPath">Path to the secret</param>
        /// <param name="unitId">Requesting unit ID</param>
        /// <returns>Decrypted secret value</returns>
        Task<string> GetSecretAsync(string secretPath, string unitId);

        /// <summary>
        /// Set a secret at the specified path
        /// </summary>
        /// <param name="secretPath">Path to store the secret</param>
        /// <param name="secretValue">Secret value to encrypt and store</param>
        /// <param name="unitId">Requesting unit ID</param>
        /// <returns>Success status</returns>
        Task<bool> SetSecretAsync(string secretPath, string secretValue, string unitId);

        /// <summary>
        /// Delete a secret
        /// </summary>
        /// <param name="secretPath">Path to the secret to delete</param>
        /// <param name="unitId">Requesting unit ID</param>
        /// <returns>Success status</returns>
        Task<bool> DeleteSecretAsync(string secretPath, string unitId);

        /// <summary>
        /// List all secrets for a unit
        /// </summary>
        /// <param name="unitId">Unit ID</param>
        /// <returns>List of secret paths</returns>
        Task<string[]> ListSecretsAsync(string unitId);

        /// <summary>
        /// Check if the service is healthy
        /// </summary>
        Task<bool> IsHealthyAsync();

        /// <summary>
        /// Get total number of secrets
        /// </summary>
        Task<int> GetSecretCountAsync();
    }
} 