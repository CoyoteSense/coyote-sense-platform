using System.Text.Json;

namespace Coyote.Infra.Http;

/// <summary>
/// HTTP request implementation
/// </summary>
public class HttpRequest : IHttpRequest
{
    public string Url { get; set; } = string.Empty;
    public HttpMethod Method { get; set; } = HttpMethod.Get;
    public string? Body { get; set; }
    public IDictionary<string, string> Headers { get; } = new Dictionary<string, string>();
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
        Headers[name] = value;
    }
}

/// <summary>
/// HTTP response implementation
/// </summary>
public class HttpResponse : IHttpResponse
{
    public int StatusCode { get; init; }
    public string Body { get; init; } = string.Empty;
    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>();
    public bool IsSuccess => StatusCode >= 200 && StatusCode < 300;
    public string? ErrorMessage { get; init; }

    public string? GetHeader(string name)
    {
        return Headers.FirstOrDefault(h => 
            string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value;
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
}

/// <summary>
/// Base HTTP client implementation with common functionality
/// </summary>
public abstract class BaseHttpClient : ICoyoteHttpClient
{
    protected readonly HttpClientOptions _options;
    protected bool _disposed;

    protected BaseHttpClient(HttpClientOptions options)
    {
        _options = options;
    }

    public abstract Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default);

    public virtual async Task<IHttpResponse> GetAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var request = CreateRequest();
        request.Url = url;
        request.Method = HttpMethod.Get;
        
        if (headers != null)
        {
            foreach (var header in headers)
            {
                request.SetHeader(header.Key, header.Value);
            }
        }

        return await ExecuteAsync(request, cancellationToken);
    }

    public virtual async Task<IHttpResponse> PostAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var request = CreateRequest();
        request.Url = url;
        request.Method = HttpMethod.Post;
        request.Body = body;
        
        if (headers != null)
        {
            foreach (var header in headers)
            {
                request.SetHeader(header.Key, header.Value);
            }
        }

        return await ExecuteAsync(request, cancellationToken);
    }

    public virtual async Task<IHttpResponse> PostJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var request = CreateRequest();
        request.Url = url;
        request.Method = HttpMethod.Post;
        request.SetJsonBody(content);
        
        if (headers != null)
        {
            foreach (var header in headers)
            {
                request.SetHeader(header.Key, header.Value);
            }
        }

        return await ExecuteAsync(request, cancellationToken);
    }

    public virtual async Task<IHttpResponse> PutAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var request = CreateRequest();
        request.Url = url;
        request.Method = HttpMethod.Put;
        request.Body = body;
        
        if (headers != null)
        {
            foreach (var header in headers)
            {
                request.SetHeader(header.Key, header.Value);
            }
        }

        return await ExecuteAsync(request, cancellationToken);
    }

    public virtual async Task<IHttpResponse> PutJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var request = CreateRequest();
        request.Url = url;
        request.Method = HttpMethod.Put;
        request.SetJsonBody(content);
        
        if (headers != null)
        {
            foreach (var header in headers)
            {
                request.SetHeader(header.Key, header.Value);
            }
        }

        return await ExecuteAsync(request, cancellationToken);
    }

    public virtual async Task<IHttpResponse> DeleteAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var request = CreateRequest();
        request.Url = url;
        request.Method = HttpMethod.Delete;
        
        if (headers != null)
        {
            foreach (var header in headers)
            {
                request.SetHeader(header.Key, header.Value);
            }
        }

        return await ExecuteAsync(request, cancellationToken);
    }

    public virtual async Task<IHttpResponse> PatchAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        var request = CreateRequest();
        request.Url = url;
        request.Method = HttpMethod.Patch;
        request.Body = body;
        
        if (headers != null)
        {
            foreach (var header in headers)
            {
                request.SetHeader(header.Key, header.Value);
            }
        }

        return await ExecuteAsync(request, cancellationToken);
    }

    public virtual void SetDefaultTimeout(int timeoutMs)
    {
        _options.DefaultTimeoutMs = timeoutMs;
    }

    public virtual void SetDefaultHeaders(IReadOnlyDictionary<string, string> headers)
    {
        _options.DefaultHeaders.Clear();
        foreach (var header in headers)
        {
            _options.DefaultHeaders[header.Key] = header.Value;
        }
    }

    public virtual void SetClientCertificate(string certPath, string keyPath)
    {
        _options.ClientCertPath = certPath;
        _options.ClientKeyPath = keyPath;
    }

    public virtual void SetCACertificate(string caPath)
    {
        _options.CACertPath = caPath;
    }

    public virtual void SetVerifyPeer(bool verify)
    {
        _options.VerifyPeer = verify;
    }

    public abstract Task<bool> PingAsync(string url, CancellationToken cancellationToken = default);

    public virtual IHttpRequest CreateRequest()
    {
        var request = new HttpRequest
        {
            TimeoutMs = _options.DefaultTimeoutMs,
            VerifyPeer = _options.VerifyPeer,
            FollowRedirects = _options.FollowRedirects,
            ClientCertPath = _options.ClientCertPath,
            ClientKeyPath = _options.ClientKeyPath,
            CACertPath = _options.CACertPath
        };

        // Add default headers
        foreach (var header in _options.DefaultHeaders)
        {
            request.SetHeader(header.Key, header.Value);
        }

        return request;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed resources
            }
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
