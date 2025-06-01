using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RestSharp;
using Coyote.Infra.Http;

namespace Coyote.Infra.Http.Modes.Real;

/// <summary>
/// Real HTTP client implementation using RestSharp
/// </summary>
public class RealHttpClient : BaseHttpClient
{
    private readonly RestClient _restClient;
    private readonly ILogger<RealHttpClient> _logger;

    public RealHttpClient(IOptions<HttpClientOptions> options, ILogger<RealHttpClient> logger)
        : base(options.Value)
    {
        _logger = logger;
          var restOptions = new RestClientOptions
        {
            UserAgent = _options.UserAgent,
            FollowRedirects = _options.FollowRedirects,
            RemoteCertificateValidationCallback = _options.VerifyPeer 
                ? null 
                : (sender, certificate, chain, sslPolicyErrors) => true
        };

        if (!string.IsNullOrEmpty(_options.BaseUrl))
        {
            restOptions.BaseUrl = new Uri(_options.BaseUrl);
        }

        // Configure client certificate if provided
        if (!string.IsNullOrEmpty(_options.ClientCertPath) && !string.IsNullOrEmpty(_options.ClientKeyPath))
        {
            try
            {
                restOptions.ClientCertificates = new System.Security.Cryptography.X509Certificates.X509CertificateCollection
                {
                    new System.Security.Cryptography.X509Certificates.X509Certificate2(_options.ClientCertPath, _options.ClientKeyPath)
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load client certificate from {CertPath}", _options.ClientCertPath);
            }
        }

        _restClient = new RestClient(restOptions);
    }

    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        var restRequest = CreateRestRequest(request);
        
        try
        {
            _logger.LogDebug("Executing {Method} request to {Url}", request.Method, request.Url);
            
            var response = await _restClient.ExecuteAsync(restRequest, cancellationToken);
            
            _logger.LogDebug("Received response with status {StatusCode} from {Url}", 
                response.StatusCode, request.Url);

            return ConvertResponse(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HTTP request failed for {Method} {Url}", request.Method, request.Url);
            
            return new HttpResponse
            {
                StatusCode = 0,
                Body = string.Empty,
                Headers = new Dictionary<string, string>(),
                ErrorMessage = ex.Message
            };
        }
    }

    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {            var request = new RestRequest(url, Method.Head);
            request.Timeout = TimeSpan.FromMilliseconds(5000); // Short timeout for ping (5 seconds)
            
            var response = await _restClient.ExecuteAsync(request, cancellationToken);
            return response.IsSuccessful;
        }
        catch
        {
            return false;
        }
    }

    private RestRequest CreateRestRequest(IHttpRequest request)
    {
        var method = ConvertHttpMethod(request.Method);
        var restRequest = new RestRequest(request.Url, method);        // Set timeout if specified
        if (request.TimeoutMs.HasValue)
        {
            restRequest.Timeout = TimeSpan.FromMilliseconds(request.TimeoutMs.Value);
        }

        // Add headers
        foreach (var header in request.Headers)
        {
            restRequest.AddHeader(header.Key, header.Value);
        }

        // Add default headers from options
        foreach (var header in _options.DefaultHeaders)
        {
            if (!request.Headers.ContainsKey(header.Key))
            {
                restRequest.AddHeader(header.Key, header.Value);
            }
        }

        // Add body if present
        if (!string.IsNullOrEmpty(request.Body))
        {
            var contentType = request.Headers.FirstOrDefault(h => 
                string.Equals(h.Key, "Content-Type", StringComparison.OrdinalIgnoreCase)).Value;
            
            if (!string.IsNullOrEmpty(contentType))
            {
                restRequest.AddStringBody(request.Body, contentType);
            }
            else
            {
                restRequest.AddStringBody(request.Body, "application/json");
            }
        }

        return restRequest;
    }

    private static Method ConvertHttpMethod(HttpMethod method)
    {
        return method switch
        {
            HttpMethod.Get => Method.Get,
            HttpMethod.Post => Method.Post,
            HttpMethod.Put => Method.Put,
            HttpMethod.Delete => Method.Delete,
            HttpMethod.Patch => Method.Patch,
            HttpMethod.Head => Method.Head,
            HttpMethod.Options => Method.Options,
            _ => Method.Get
        };
    }

    private static IHttpResponse ConvertResponse(RestResponse response)
    {
        var headers = new Dictionary<string, string>();
        
        if (response.Headers != null)
        {
            foreach (var header in response.Headers)
            {
                if (header.Name != null && header.Value != null)
                {
                    headers[header.Name] = header.Value.ToString()!;
                }
            }
        }

        return new HttpResponse
        {
            StatusCode = (int)response.StatusCode,
            Body = response.Content ?? string.Empty,
            Headers = headers,
            ErrorMessage = response.ErrorMessage
        };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _restClient?.Dispose();
        }
        
        base.Dispose(disposing);
    }
}