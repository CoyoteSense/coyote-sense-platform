using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Coyote.Units.KeyVault.Services
{
    /// <summary>
    /// Main KeyVault service implementation
    /// </summary>
    public class KeyVaultService : IKeyVaultService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<KeyVaultService> _logger;
        private readonly IAuthService _authService;
        private readonly ISecretService _secretService;
        private readonly KeyVaultStats _stats;

        public KeyVaultService(
            IConfiguration configuration,
            ILogger<KeyVaultService> logger,
            IAuthService authService,
            ISecretService secretService)
        {
            _configuration = configuration;
            _logger = logger;
            _authService = authService;
            _secretService = secretService;
            _stats = new KeyVaultStats
            {
                StartTime = DateTime.UtcNow
            };
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing KeyVault service...");

            try
            {
                // Initialize authentication service
                await _authService.InitializeAsync();

                // Initialize secret service
                await _secretService.InitializeAsync();

                _logger.LogInformation("KeyVault service initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize KeyVault service");
                throw;
            }
        }

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                var authHealthy = await _authService.IsHealthyAsync();
                var secretHealthy = await _secretService.IsHealthyAsync();

                return authHealthy && secretHealthy;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Health check failed");
                return false;
            }
        }

        public async Task<KeyVaultStats> GetStatsAsync()
        {
            _stats.TotalSecrets = await _secretService.GetSecretCountAsync();
            _stats.ActiveTokens = await _authService.GetActiveTokenCountAsync();
            
            return _stats;
        }
    }
} 