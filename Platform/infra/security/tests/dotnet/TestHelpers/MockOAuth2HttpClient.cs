using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Coyote.Infra.Http;
using System.Text.Json;

namespace Coyote.Infra.Security.Tests.TestHelpers;

/// <summary>
/// Mock HTTP client for OAuth2 testing that returns proper OAuth2 responses
/// </summary>
public class MockOAuth2HttpClient : ICoyoteHttpClient
{
    private readonly ILogger<MockOAuth2HttpClient> _logger;
    private readonly Dictionary<string, object> _mockResponses;
    private bool _disposed;

    public MockOAuth2HttpClient(ILogger<MockOAuth2HttpClient>? logger = null)
    {
        _logger = logger ?? NullLogger<MockOAuth2HttpClient>.Instance;
        _mockResponses = new Dictionary<string, object>();
        SetupDefaultOAuth2Responses();
    }

    private void SetupDefaultOAuth2Responses()
    {
        // OAuth2 Discovery Response
        var discoveryResponse = new
        {
            issuer = "https://test-auth.example.com",
            token_endpoint = "https://test-auth.example.com/oauth2/token",
            introspection_endpoint = "https://test-auth.example.com/oauth2/introspect",
            revocation_endpoint = "https://test-auth.example.com/oauth2/revoke",
            jwks_uri = "https://test-auth.example.com/.well-known/jwks.json",
            grant_types_supported = new[] { "client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
            scopes_supported = new[] { "api.read", "api.write", "openid", "profile" },
            response_types_supported = new[] { "code" }
        };

        // Token Response for Client Credentials
        var tokenResponse = new
        {
            access_token = "test-access-token-" + Guid.NewGuid().ToString("N")[..8],
            token_type = "Bearer",
            expires_in = 3600,
            scope = "api.read api.write"
        };

        // Token Introspection Response
        var introspectionResponse = new
        {
            active = true,
            client_id = "test-client-id",
            scope = "api.read api.write",
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            sub = "test-subject",
            aud = "api",
            iss = "https://test-auth.example.com",
            token_type = "Bearer"
        };

        // Store responses
        _mockResponses["/.well-known/openid_configuration"] = discoveryResponse;
        _mockResponses["/oauth2/token"] = tokenResponse;
        _mockResponses["/oauth2/introspect"] = introspectionResponse;
        _mockResponses["/oauth2/revoke"] = new { revoked = true };
        _mockResponses["/health"] = new { status = "healthy", timestamp = DateTimeOffset.UtcNow };
    }

    public void SetMockResponse(string endpoint, object response)
    {
        _mockResponses[endpoint] = response;
    }

    public async Task<HttpResponse> ExecuteAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(MockOAuth2HttpClient));

        _logger.LogDebug("Mock HTTP request: {Method} {Url}", request.Method, request.Url);

        try
        {
            var uri = new Uri(request.Url);
            var path = uri.AbsolutePath;

            // Find matching mock response
            if (_mockResponses.TryGetValue(path, out var responseData))
            {
                var json = JsonSerializer.Serialize(responseData, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                _logger.LogDebug("Returning mock response for {Path}: {Response}", path, json);

                return new HttpResponse
                {
                    StatusCode = 200,
                    Body = json,
                    Headers = new Dictionary<string, string>
                    {
                        ["Content-Type"] = "application/json"
                    },
                    IsSuccess = true
                };
            }

            // Default response for unmatched requests
            _logger.LogWarning("No mock response configured for path: {Path}", path);
            return new HttpResponse
            {
                StatusCode = 404,
                Body = JsonSerializer.Serialize(new { error = "not_found", error_description = "Mock endpoint not configured" }),
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json"
                },
                IsSuccess = false
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing mock request");
            return new HttpResponse
            {
                StatusCode = 500,
                Body = JsonSerializer.Serialize(new { error = "internal_error", error_description = ex.Message }),
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json"
                },
                IsSuccess = false
            };
        }
    }

    // ICoyoteHttpClient implementation
    public Task<HttpResponse> GetAsync(string url, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(new HttpRequest { Method = HttpMethod.Get, Url = url }, cancellationToken);
    }

    public Task<HttpResponse> PostAsync(string url, string body, string? contentType = null, CancellationToken cancellationToken = default)
    {
        var request = new HttpRequest
        {
            Method = HttpMethod.Post,
            Url = url,
            Body = body,
            Headers = new Dictionary<string, string>()
        };

        if (!string.IsNullOrEmpty(contentType))
        {
            request.Headers["Content-Type"] = contentType;
        }

        return ExecuteAsync(request, cancellationToken);
    }

    public Task<HttpResponse> PutAsync(string url, string body, string? contentType = null, CancellationToken cancellationToken = default)
    {
        var request = new HttpRequest
        {
            Method = HttpMethod.Put,
            Url = url,
            Body = body,
            Headers = new Dictionary<string, string>()
        };

        if (!string.IsNullOrEmpty(contentType))
        {
            request.Headers["Content-Type"] = contentType;
        }

        return ExecuteAsync(request, cancellationToken);
    }

    public Task<HttpResponse> DeleteAsync(string url, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(new HttpRequest { Method = HttpMethod.Delete, Url = url }, cancellationToken);
    }

    public Task<HttpResponse> PatchAsync(string url, string body, string? contentType = null, CancellationToken cancellationToken = default)
    {
        var request = new HttpRequest
        {
            Method = HttpMethod.Patch,
            Url = url,
            Body = body,
            Headers = new Dictionary<string, string>()
        };

        if (!string.IsNullOrEmpty(contentType))
        {
            request.Headers["Content-Type"] = contentType;
        }

        return ExecuteAsync(request, cancellationToken);
    }

    public Task<HttpResponse> HeadAsync(string url, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(new HttpRequest { Method = HttpMethod.Head, Url = url }, cancellationToken);
    }

    public Task<HttpResponse> OptionsAsync(string url, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(new HttpRequest { Method = HttpMethod.Options, Url = url }, cancellationToken);
    }

    public void SetDefaultTimeout(int timeoutMs)
    {
        _logger.LogDebug("Setting default timeout: {TimeoutMs}ms", timeoutMs);
    }

    public void SetDefaultHeaders(IReadOnlyDictionary<string, string> headers)
    {
        _logger.LogDebug("Setting default headers: {Headers}", string.Join(", ", headers.Select(h => $"{h.Key}={h.Value}")));
    }

    public void SetClientCertificate(string certPath, string keyPath)
    {
        _logger.LogDebug("Setting client certificate: {CertPath}", certPath);
    }

    public void SetCACertificate(string caPath)
    {
        _logger.LogDebug("Setting CA certificate: {CaPath}", caPath);
    }

    public void SetVerifyPeer(bool verify)
    {
        _logger.LogDebug("Setting verify peer: {Verify}", verify);
    }

    public async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await GetAsync(url, cancellationToken);
            return response.IsSuccess;
        }
        catch
        {
            return false;
        }
    }

    public IHttpRequest CreateRequest()
    {
        return new MockHttpRequest();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _mockResponses.Clear();
            _disposed = true;
            _logger.LogDebug("MockOAuth2HttpClient disposed");
        }
    }
}

/// <summary>
/// Mock HTTP request implementation
/// </summary>
public class MockHttpRequest : IHttpRequest
{
    private readonly Dictionary<string, string> _headers = new();
    private string _body = string.Empty;

    public string Url { get; set; } = string.Empty;
    public HttpMethod Method { get; set; } = HttpMethod.Get;
    public IReadOnlyDictionary<string, string> Headers => _headers;
    public string Body => _body;

    public IHttpRequest SetUrl(string url)
    {
        Url = url;
        return this;
    }

    public IHttpRequest SetMethod(HttpMethod method)
    {
        Method = method;
        return this;
    }

    public IHttpRequest AddHeader(string name, string value)
    {
        _headers[name] = value;
        return this;
    }

    public IHttpRequest SetBody(string body)
    {
        _body = body;
        return this;
    }

    public Task<HttpResponse> ExecuteAsync(CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException("Use MockOAuth2HttpClient.ExecuteAsync instead");
    }
}
