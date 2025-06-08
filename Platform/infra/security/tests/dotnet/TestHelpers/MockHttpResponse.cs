using System.Text.Json;
using Coyote.Infra.Http;

namespace Coyote.Infra.Security.Tests.TestHelpers;

/// <summary>
/// Mock implementation of IHttpResponse for testing
/// </summary>
public class MockHttpResponse : IHttpResponse
{
    private readonly Dictionary<string, string> _headers = new(StringComparer.OrdinalIgnoreCase);

    public int StatusCode { get; set; }
    public string Body { get; set; } = string.Empty;
    public IReadOnlyDictionary<string, string> Headers => _headers;
    public bool IsSuccess => StatusCode >= 200 && StatusCode < 300;
    public string? ErrorMessage { get; set; }

    public MockHttpResponse(int statusCode, string body = "", Dictionary<string, string>? headers = null)
    {
        StatusCode = statusCode;
        Body = body;

        if (headers != null)
        {
            foreach (var header in headers)
            {
                _headers[header.Key] = header.Value;
            }
        }

        // Set default Content-Type if not specified
        if (!_headers.ContainsKey("Content-Type") && !string.IsNullOrEmpty(body))
        {
            _headers["Content-Type"] = "application/json";
        }
    }

    public string? GetHeader(string name)
    {
        return _headers.TryGetValue(name, out var value) ? value : null;
    }

    public T? GetContent<T>()
    {
        if (string.IsNullOrEmpty(Body))
            return default;

        try
        {
            return JsonSerializer.Deserialize<T>(Body);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    public void SetHeader(string name, string value)
    {
        _headers[name] = value;
    }
}
