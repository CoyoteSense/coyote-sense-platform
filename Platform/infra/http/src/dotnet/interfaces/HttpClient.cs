using System.Text.Json;

namespace Coyote.Infra.Http;

/// <summary>
/// HTTP method enumeration
/// </summary>
public enum HttpMethod
{
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options
}

/// <summary>
/// HTTP response contract
/// </summary>
public interface IHttpResponse
{
    /// <summary>
    /// HTTP status code
    /// </summary>
    int StatusCode { get; }
    
    /// <summary>
    /// Response body as string
    /// </summary>
    string Body { get; }
    
    /// <summary>
    /// Response headers
    /// </summary>
    IReadOnlyDictionary<string, string> Headers { get; }
    
    /// <summary>
    /// Indicates if the response represents a successful HTTP status (2xx)
    /// </summary>
    bool IsSuccess { get; }
    
    /// <summary>
    /// Error message if the request failed
    /// </summary>
    string? ErrorMessage { get; }
    
    /// <summary>
    /// Get header value by name (case-insensitive)
    /// </summary>
    string? GetHeader(string name);
    
    /// <summary>
    /// Deserialize response body to specified type
    /// </summary>
    T? GetContent<T>();
}

/// <summary>
/// HTTP request configuration
/// </summary>
public interface IHttpRequest
{
    /// <summary>
    /// Request URL
    /// </summary>
    string Url { get; set; }
    
    /// <summary>
    /// HTTP method
    /// </summary>
    HttpMethod Method { get; set; }
    
    /// <summary>
    /// Request body
    /// </summary>
    string? Body { get; set; }
    
    /// <summary>
    /// Request headers
    /// </summary>
    IDictionary<string, string> Headers { get; }
    
    /// <summary>
    /// Request timeout in milliseconds
    /// </summary>
    int? TimeoutMs { get; set; }
    
    /// <summary>
    /// Client certificate path
    /// </summary>
    string? ClientCertPath { get; set; }
    
    /// <summary>
    /// Client certificate key path
    /// </summary>
    string? ClientKeyPath { get; set; }
    
    /// <summary>
    /// CA certificate path for server verification
    /// </summary>
    string? CACertPath { get; set; }
    
    /// <summary>
    /// Whether to verify server certificate
    /// </summary>
    bool VerifyPeer { get; set; }
    
    /// <summary>
    /// Whether to follow redirects
    /// </summary>
    bool FollowRedirects { get; set; }
    
    /// <summary>
    /// Set request body as JSON
    /// </summary>
    void SetJsonBody<T>(T content);
    
    /// <summary>
    /// Add or update header
    /// </summary>
    void SetHeader(string name, string value);
}

/// <summary>
/// Main HTTP client interface for the Coyote platform
/// </summary>
public interface ICoyoteHttpClient : IDisposable
{
    /// <summary>
    /// Execute a configured HTTP request
    /// </summary>
    Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Perform GET request
    /// </summary>
    Task<IHttpResponse> GetAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Perform POST request
    /// </summary>
    Task<IHttpResponse> PostAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Perform POST request with JSON body
    /// </summary>
    Task<IHttpResponse> PostJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Perform PUT request
    /// </summary>
    Task<IHttpResponse> PutAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Perform PUT request with JSON body
    /// </summary>
    Task<IHttpResponse> PutJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Perform DELETE request
    /// </summary>
    Task<IHttpResponse> DeleteAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Perform PATCH request
    /// </summary>
    Task<IHttpResponse> PatchAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Set default timeout for all requests
    /// </summary>
    void SetDefaultTimeout(int timeoutMs);
    
    /// <summary>
    /// Set default headers for all requests
    /// </summary>
    void SetDefaultHeaders(IReadOnlyDictionary<string, string> headers);
    
    /// <summary>
    /// Set client certificate for mTLS
    /// </summary>
    void SetClientCertificate(string certPath, string keyPath);
    
    /// <summary>
    /// Set CA certificate for server verification
    /// </summary>
    void SetCACertificate(string caPath);
    
    /// <summary>
    /// Set whether to verify server certificates
    /// </summary>
    void SetVerifyPeer(bool verify);
    
    /// <summary>
    /// Test connectivity to specified URL
    /// </summary>
    Task<bool> PingAsync(string url, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Create a new request builder
    /// </summary>
    IHttpRequest CreateRequest();
}