using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Real;

namespace Coyote.Infra.Http.Modes.Record;

/// <summary>
/// Recording HTTP client implementation that captures requests/responses
/// </summary>
public class RecordingHttpClient : BaseHttpClient
{    private readonly RealHttpClient _realClient;
    private readonly RecordingModeOptions _recordingOptions;
    private readonly ILogger<RecordingHttpClient> _logger;

    public RecordingHttpClient(IOptions<HttpClientOptions> options, IOptions<HttpClientModeOptions> modeOptions, ILogger<RecordingHttpClient> logger, IServiceProvider serviceProvider)
        : base(options.Value)
    {
        _recordingOptions = modeOptions.Value.Recording;
        _logger = logger;
        
        // Create logger for real client
        var realClientLogger = serviceProvider.GetService<ILogger<RealHttpClient>>() ?? 
            Microsoft.Extensions.Logging.Abstractions.NullLogger<RealHttpClient>.Instance;
        
        // Use real client for actual requests
        _realClient = new RealHttpClient(options, realClientLogger);
    }

    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        var response = await _realClient.ExecuteAsync(request, cancellationToken);

        // Record the request/response pair
        await RecordInteraction(request, response);

        return response;
    }

    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        return await _realClient.PingAsync(url, cancellationToken);
    }

    private async Task RecordInteraction(IHttpRequest request, IHttpResponse response)
    {
        try
        {
            if (string.IsNullOrEmpty(_recordingOptions.RecordingPath))
            {
                _logger.LogWarning("Recording path not configured, skipping recording");
                return;
            }

            var recording = new
            {
                Timestamp = DateTime.UtcNow,
                Request = new
                {
                    request.Url,
                    Method = request.Method.ToString(),
                    Headers = _recordingOptions.RecordHeaders ? request.Headers : null,
                    Body = _recordingOptions.RecordBodies ? request.Body : null
                },
                Response = new
                {
                    response.StatusCode,
                    Headers = _recordingOptions.RecordHeaders ? response.Headers : null,
                    Body = _recordingOptions.RecordBodies ? response.Body : null,
                    response.ErrorMessage
                }
            };

            var json = System.Text.Json.JsonSerializer.Serialize(recording, new System.Text.Json.JsonSerializerOptions 
            { 
                WriteIndented = true 
            });

            var fileName = $"http_recording_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}.json";
            var filePath = Path.Combine(_recordingOptions.RecordingPath, fileName);

            Directory.CreateDirectory(_recordingOptions.RecordingPath);
            await File.WriteAllTextAsync(filePath, json, cancellationToken: default);

            _logger.LogDebug("HTTP interaction recorded to {FilePath}", filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to record HTTP interaction");
        }
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