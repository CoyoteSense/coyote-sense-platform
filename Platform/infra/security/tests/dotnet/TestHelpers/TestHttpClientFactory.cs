using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;

namespace Coyote.Infra.Security.Tests.TestHelpers;

/// <summary>
/// Test HTTP client factory for OAuth2 testing
/// </summary>
public class TestHttpClientFactory : Coyote.Infra.Http.Factory.IHttpClientFactory
{
    private readonly ICoyoteHttpClient _httpClient;
    private readonly ILogger<TestHttpClientFactory> _logger;

    public TestHttpClientFactory(ICoyoteHttpClient httpClient, ILogger<TestHttpClientFactory>? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? NullLogger<TestHttpClientFactory>.Instance;
    }

    public ICoyoteHttpClient CreateHttpClient()
    {
        _logger.LogDebug("Creating test HTTP client");
        return _httpClient;
    }

    public ICoyoteHttpClient CreateHttpClientForMode(RuntimeMode mode)
    {
        _logger.LogDebug("Creating test HTTP client for mode: {Mode}", mode);
        return _httpClient;
    }

    public ICoyoteHttpClient CreateHttpClient(string clientName)
    {
        _logger.LogDebug("Creating test HTTP client with name: {ClientName}", clientName);
        return _httpClient;
    }    public ICoyoteHttpClient CreateHttpClient(HttpClientOptions options)
    {
        _logger.LogDebug("Creating test HTTP client with options");
        return _httpClient;
    }

    public RuntimeMode GetCurrentMode()
    {
        return RuntimeMode.Testing;
    }
}
