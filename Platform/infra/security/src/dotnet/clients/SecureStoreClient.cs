// Alias for the main namespace SecureStoreClient

namespace Coyote.Infra.Security.Auth.Clients
{
    /// <summary>
    /// Alias for the SecureStoreClient in the main namespace
    /// </summary>
    public class SecureStoreClient : Auth.SecureStoreClient
    {
        public SecureStoreClient(SecureStoreOptions options, IAuthClient authClient, Microsoft.Extensions.Logging.ILogger<SecureStoreClient> logger)
            : base(options, authClient, logger)
        {
        }
    }
}
