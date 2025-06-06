using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Coyote.Infra.Security.Auth;

namespace Coyote.Infra.Security.Modes.Real
{
    /// <summary>
    /// Real implementation of security client for production environments
    /// </summary>
    public class SecurityClientReal : IDisposable
    {
        private readonly IAuthClient _authClient;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the SecurityClientReal class
        /// </summary>
        /// <param name="authClient">The authentication client to wrap</param>
        /// <exception cref="ArgumentNullException">Thrown when authClient is null</exception>
        public SecurityClientReal(IAuthClient authClient)
        {
            _authClient = authClient ?? throw new ArgumentNullException(nameof(authClient));
        }

        /// <summary>
        /// Gets the current authentication token
        /// </summary>
        public AuthToken? CurrentToken => _authClient.CurrentToken;

        /// <summary>
        /// Whether the client is currently authenticated
        /// </summary>
        public bool IsAuthenticated => _authClient.IsAuthenticated;

        /// <summary>
        /// Authenticates using client credentials flow
        /// </summary>
        /// <param name="scopes">Optional scopes to request</param>
        /// <returns>Authentication result</returns>
        public async Task<AuthResult> AuthenticateAsync(string[]? scopes = null)
        {
            ThrowIfDisposed();
            var scopeList = scopes != null ? new List<string>(scopes) : null;
            return await _authClient.AuthenticateClientCredentialsAsync(scopeList);
        }

        /// <summary>
        /// Refreshes the current token if possible
        /// </summary>
        /// <returns>Refreshed token or null if refresh failed</returns>
        public async Task<AuthToken?> RefreshTokenAsync()
        {
            ThrowIfDisposed();
            return await _authClient.GetValidTokenAsync();
        }

        /// <summary>
        /// Tests connection to the authentication server
        /// </summary>
        /// <returns>True if connection is successful</returns>
        public async Task<bool> TestConnectionAsync()
        {
            ThrowIfDisposed();
            return await _authClient.TestConnectionAsync();
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SecurityClientReal));
        }

        /// <summary>
        /// Releases all resources used by the SecurityClientReal
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _authClient?.Dispose();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}