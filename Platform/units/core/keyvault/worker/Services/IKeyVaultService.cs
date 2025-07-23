using System.Threading.Tasks;

namespace Coyote.Units.KeyVault.Services
{
    /// <summary>
    /// Main KeyVault service interface
    /// </summary>
    public interface IKeyVaultService
    {
        /// <summary>
        /// Initialize the KeyVault service
        /// </summary>
        Task InitializeAsync();

        /// <summary>
        /// Check if the service is healthy
        /// </summary>
        Task<bool> IsHealthyAsync();

        /// <summary>
        /// Get service statistics
        /// </summary>
        Task<KeyVaultStats> GetStatsAsync();
    }

    /// <summary>
    /// KeyVault service statistics
    /// </summary>
    public class KeyVaultStats
    {
        public int TotalSecrets { get; set; }
        public int ActiveTokens { get; set; }
        public long RequestsPerSecond { get; set; }
        public int AuthenticationFailures { get; set; }
        public double AverageResponseTimeMs { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan Uptime => DateTime.UtcNow - StartTime;
    }
} 