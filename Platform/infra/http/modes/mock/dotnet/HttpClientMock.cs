using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Coyote.Infra.Http;

namespace Coyote.Infra.Http.Modes.Mock;

/// <summary>
/// Mock HTTP client implementation for testing
/// </summary>
public class MockHttpClient : BaseHttpClient
{
    private readonly MockResponseOptions _mockOptions;
    private readonly ILogger<MockHttpClient> _logger;

    public MockHttpClient(IOptions<HttpClientOptions> options, IOptions<HttpClientModeOptions> modeOptions, ILogger<MockHttpClient> logger)
        : base(options.Value)
    {
        _mockOptions = modeOptions.Value.Mock;
        _logger = logger;
    }

    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Mock HTTP client executing {Method} request to {Url}", request.Method, request.Url);

        // Check for predefined responses first
        var response = GetPredefinedResponse(request.Url);
        
        if (response == null)
        {
            // Use default response
            response = new MockResponse
            {
                StatusCode = _mockOptions.DefaultStatusCode,
                Body = _mockOptions.DefaultBody,
                Headers = new Dictionary<string, string>(_mockOptions.DefaultHeaders),
                DelayMs = _mockOptions.DelayMs
            };
        }

        // Simulate network delay
        if (response.DelayMs > 0)
        {
            await Task.Delay(response.DelayMs, cancellationToken);
        }

        _logger.LogDebug("Mock HTTP client returning status {StatusCode} for {Url}", response.StatusCode, request.Url);

        return new HttpResponse
        {
            StatusCode = response.StatusCode,
            Body = response.Body,
            Headers = response.Headers,
            ErrorMessage = response.StatusCode >= 400 ? $"Mock error response {response.StatusCode}" : null
        };
    }

    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Mock HTTP client ping to {Url}", url);
        
        // Simulate small delay
        await Task.Delay(10, cancellationToken);
        
        // Always return true for mock ping
        return true;
    }

    /// <summary>
    /// Configure a predefined response for a specific URL
    /// </summary>
    public void SetPredefinedResponse(string url, int statusCode, string body, Dictionary<string, string>? headers = null, int delayMs = 0)
    {
        _mockOptions.PredefinedResponses[url] = new MockResponse
        {
            StatusCode = statusCode,
            Body = body,
            Headers = headers ?? new Dictionary<string, string>(),
            DelayMs = delayMs
        };
    }

    /// <summary>
    /// Configure a predefined response for a specific URL with JSON body
    /// </summary>
    public void SetPredefinedJsonResponse<T>(string url, T content, int statusCode = 200, Dictionary<string, string>? headers = null, int delayMs = 0)
    {
        var responseHeaders = headers ?? new Dictionary<string, string>();
        responseHeaders["Content-Type"] = "application/json";

        SetPredefinedResponse(url, statusCode, System.Text.Json.JsonSerializer.Serialize(content), responseHeaders, delayMs);
    }

    /// <summary>
    /// Configure default response for all requests
    /// </summary>
    public void SetDefaultResponse(int statusCode, string body, Dictionary<string, string>? headers = null, int delayMs = 0)
    {
        _mockOptions.DefaultStatusCode = statusCode;
        _mockOptions.DefaultBody = body;
        _mockOptions.DelayMs = delayMs;
        
        if (headers != null)
        {
            _mockOptions.DefaultHeaders.Clear();
            foreach (var header in headers)
            {
                _mockOptions.DefaultHeaders[header.Key] = header.Value;
            }
        }
    }

    /// <summary>
    /// Clear all predefined responses
    /// </summary>
    public void ClearPredefinedResponses()
    {
        _mockOptions.PredefinedResponses.Clear();
    }

    /// <summary>
    /// Get all configured URLs with predefined responses
    /// </summary>
    public IReadOnlyCollection<string> GetConfiguredUrls()
    {
        return _mockOptions.PredefinedResponses.Keys.ToList().AsReadOnly();
    }

    private MockResponse? GetPredefinedResponse(string url)
    {
        // Exact match first
        if (_mockOptions.PredefinedResponses.TryGetValue(url, out var exactMatch))
        {
            return exactMatch;
        }

        // Try pattern matching (simple contains check)
        foreach (var kvp in _mockOptions.PredefinedResponses)
        {
            if (url.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase) ||
                kvp.Key.Contains("*") && MatchesWildcard(url, kvp.Key))
            {
                return kvp.Value;
            }
        }

        return null;
    }

    private static bool MatchesWildcard(string url, string pattern)
    {
        // Simple wildcard matching - replace * with .*
        var regexPattern = "^" + pattern.Replace("*", ".*") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(url, regexPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }
}