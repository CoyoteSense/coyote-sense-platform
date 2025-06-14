using System.Text.Json;
using Coyote.Infra.Http;
using HttpMethod = Coyote.Infra.Http.HttpMethod;

namespace Coyote.Infra.Security.Tests.TestHelpers;

/// <summary>
/// Mock implementation of IHttpRequest for testing
/// </summary>
public class MockHttpRequest : IHttpRequest
{
    private readonly Dictionary<string, string> _headers = new(StringComparer.OrdinalIgnoreCase);

    public string Url { get; set; } = string.Empty;
    public HttpMethod Method { get; set; } = HttpMethod.Get;
    public string? Body { get; set; }
    public IDictionary<string, string> Headers => _headers;
    public int? TimeoutMs { get; set; }
    public string? ClientCertPath { get; set; }
    public string? ClientKeyPath { get; set; }
    public string? CACertPath { get; set; }
    public bool VerifyPeer { get; set; } = true;
    public bool FollowRedirects { get; set; } = true;

    public void SetJsonBody<T>(T content)
    {
        Body = JsonSerializer.Serialize(content);
        SetHeader("Content-Type", "application/json");
    }

    public void SetHeader(string name, string value)
    {
        _headers[name] = value;
    }
}
