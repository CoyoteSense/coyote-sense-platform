using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Real;

namespace Coyote.Infra.Http.Modes.Debug;

/// <summary>
/// Debug HTTP client implementation with enhanced logging
/// </summary>
public class DebugHttpClient : BaseHttpClient
{
    private readonly RealHttpClient _realClient;
    private readonly DebugModeOptions _debugOptions;
    private readonly ILogger<DebugHttpClient> _logger;    public DebugHttpClient(IOptions<HttpClientOptions> options, IOptions<HttpClientModeOptions> modeOptions, ILogger<DebugHttpClient> logger, IServiceProvider serviceProvider)
        : base(options.Value)
    {
        _debugOptions = modeOptions.Value.Debug;
        _logger = logger;
        
        // Create logger for real client
        var realClientLogger = serviceProvider.GetService<ILogger<RealHttpClient>>() ?? 
            Microsoft.Extensions.Logging.Abstractions.NullLogger<RealHttpClient>.Instance;
        
        // Use real client for actual requests
        _realClient = new RealHttpClient(options, realClientLogger);
    }

    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        if (_debugOptions.LogRequests)
        {
            _logger.LogInformation("DEBUG HTTP Request: {Method} {Url}", request.Method, request.Url);
            
            if (_debugOptions.LogHeaders)
            {
                foreach (var header in request.Headers)
                {
                    _logger.LogInformation("DEBUG Request Header: {Key} = {Value}", header.Key, header.Value);
                }
            }
            
            if (_debugOptions.LogBodies && !string.IsNullOrEmpty(request.Body))
            {
                _logger.LogInformation("DEBUG Request Body: {Body}", request.Body);
            }
        }

        var response = await _realClient.ExecuteAsync(request, cancellationToken);

        if (_debugOptions.LogResponses)
        {
            _logger.LogInformation("DEBUG HTTP Response: {StatusCode} from {Url}", response.StatusCode, request.Url);
            
            if (_debugOptions.LogHeaders)
            {
                foreach (var header in response.Headers)
                {
                    _logger.LogInformation("DEBUG Response Header: {Key} = {Value}", header.Key, header.Value);
                }
            }
            
            if (_debugOptions.LogBodies && !string.IsNullOrEmpty(response.Body))
            {
                _logger.LogInformation("DEBUG Response Body: {Body}", response.Body);
            }
        }

        return response;
    }

    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("DEBUG HTTP Ping to {Url}", url);
        var result = await _realClient.PingAsync(url, cancellationToken);
        _logger.LogInformation("DEBUG HTTP Ping result for {Url}: {Result}", url, result);
        return result;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _realClient?.Dispose();
        }
        
        base.Dispose(disposing);
    }
}