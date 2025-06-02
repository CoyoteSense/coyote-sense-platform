using System;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Http;
using IHttpClientFactory = Coyote.Infra.Http.Factory.IHttpClientFactory;

namespace Coyote.Infra.Security.Tests.TestHelpers
{
    /// <summary>
    /// Test implementation of HTTP client factory that returns the provided HTTP client
    /// Simplifies testing with dependency injection
    /// </summary>
    public class TestHttpClientFactory : IHttpClientFactory
    {
        private readonly ICoyoteHttpClient _httpClient;
        private readonly ILogger<TestHttpClientFactory>? _logger;
        private readonly RuntimeMode _defaultMode;

        /// <summary>
        /// Create a new TestHttpClientFactory with a pre-configured HTTP client
        /// </summary>
        /// <param name="httpClient">The HTTP client to return from factory methods</param>
        /// <param name="defaultMode">The default runtime mode</param>
        /// <param name="logger">Optional logger</param>
        public TestHttpClientFactory(
            ICoyoteHttpClient httpClient, 
            RuntimeMode defaultMode = RuntimeMode.Testing,
            ILogger<TestHttpClientFactory>? logger = null)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _defaultMode = defaultMode;
            _logger = logger;
            
            _logger?.LogDebug("Created TestHttpClientFactory with mode: {Mode}", defaultMode);
        }

        /// <summary>
        /// Create an HTTP client using the default runtime mode
        /// </summary>
        public ICoyoteHttpClient CreateHttpClient()
        {
            _logger?.LogDebug("Creating HTTP client with default mode: {Mode}", _defaultMode);
            return _httpClient;
        }

        /// <summary>
        /// Create an HTTP client for a specific runtime mode
        /// </summary>
        public ICoyoteHttpClient CreateHttpClientForMode(RuntimeMode mode)
        {
            _logger?.LogDebug("Creating HTTP client for mode: {Mode}", mode);
            return _httpClient;
        }

        /// <summary>
        /// Get the current runtime mode
        /// </summary>
        public RuntimeMode GetCurrentMode()
        {
            return _defaultMode;
        }
    }
}