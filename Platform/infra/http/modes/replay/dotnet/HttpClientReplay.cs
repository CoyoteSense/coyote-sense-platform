using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json;
using Coyote.Infra.Http;

namespace Coyote.Infra.Http.Modes.Replay;

/// <summary>
/// Represents a recorded HTTP interaction
/// </summary>
public class RecordedInteraction
{
    public DateTime Timestamp { get; set; }
    public RecordedRequest Request { get; set; } = new();
    public RecordedResponse Response { get; set; } = new();
}

/// <summary>
/// Represents a recorded HTTP request
/// </summary>
public class RecordedRequest
{
    public string Url { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public Dictionary<string, string>? Headers { get; set; }
    public string? Body { get; set; }
}

/// <summary>
/// Represents a recorded HTTP response
/// </summary>
public class RecordedResponse
{
    public int StatusCode { get; set; }
    public Dictionary<string, string>? Headers { get; set; }
    public string? Body { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Replay HTTP client implementation that replays recorded requests/responses
/// </summary>
public class ReplayHttpClient : BaseHttpClient
{
    private readonly ReplayModeOptions _replayOptions;
    private readonly ILogger<ReplayHttpClient> _logger;
    private readonly List<RecordedInteraction> _recordings = new();
    private readonly Dictionary<string, Queue<RecordedInteraction>> _urlMappings = new();
    private int _globalIndex = 0;

    public ReplayHttpClient(IOptions<HttpClientOptions> options, IOptions<HttpClientModeOptions> modeOptions, ILogger<ReplayHttpClient> logger)
        : base(options.Value)
    {
        _replayOptions = modeOptions.Value.Replay;
        _logger = logger;

        _ = LoadRecordingsAsync();
    }    
    
    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Replay HTTP client executing {Method} request to {Url}", request.Method, request.Url);

        var response = FindMatchingResponse(request);
        if (response == null)
        {
            _logger.LogWarning("No recorded response found for {Method} {Url}, returning default", request.Method, request.Url);
            return await Task.FromResult(CreateDefaultResponse());
        }

        _logger.LogDebug("Replay HTTP client returning recorded status {StatusCode} for {Url}", response.StatusCode, request.Url);        return await Task.FromResult(new HttpResponse
        {
            StatusCode = response.StatusCode,
            Body = response.Body ?? string.Empty,
            Headers = response.Headers ?? new Dictionary<string, string>(),
            ErrorMessage = response.ErrorMessage
        });
    }
    
    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Replay HTTP client ping to {Url}", url);
        
        // Check if we have a recorded response for this URL
        var dummyRequest = new HttpRequest { Url = url, Method = HttpMethod.Head };
        var response = FindMatchingResponse(dummyRequest);
        
        return await Task.FromResult(response?.StatusCode < 400);
    }

    /// <summary>
    /// Load recordings from files
    /// </summary>
    public async Task LoadRecordingsAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(_replayOptions.RecordingPath) || !Directory.Exists(_replayOptions.RecordingPath))
            {
                _logger.LogWarning("Recording path not found: {Path}", _replayOptions.RecordingPath);
                return;
            }

            var recordingFiles = Directory.GetFiles(_replayOptions.RecordingPath, "*.json")
                .OrderBy(f => File.GetCreationTime(f))
                .ToArray();
            
            foreach (var file in recordingFiles)
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file);
                    var recording = JsonSerializer.Deserialize<RecordedInteraction>(json, new JsonSerializerOptions 
                    { 
                        PropertyNameCaseInsensitive = true 
                    });

                    if (recording != null)
                    {
                        _recordings.Add(recording);
                        
                        // Index by URL for faster lookup
                        var url = recording.Request.Url;
                        if (!_urlMappings.ContainsKey(url))
                        {
                            _urlMappings[url] = new Queue<RecordedInteraction>();
                        }
                        _urlMappings[url].Enqueue(recording);

                        _logger.LogDebug("Loaded recording for {Method} {Url} with status {StatusCode}", 
                            recording.Request.Method, recording.Request.Url, recording.Response.StatusCode);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to load recording from {File}", file);
                }
            }

            _logger.LogInformation("Loaded {Count} recordings from {Path}", _recordings.Count, _replayOptions.RecordingPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load recordings from {Path}", _replayOptions.RecordingPath);
        }
    }

    /// <summary>
    /// Find a matching recorded response for the request
    /// </summary>
    private RecordedResponse? FindMatchingResponse(IHttpRequest request)
    {
        // Strategy 1: Exact URL match with FIFO queue
        if (_urlMappings.TryGetValue(request.Url, out var queue) && queue.Count > 0)
        {
            var recording = queue.Dequeue();
            return recording.Response;
        }

        // Strategy 2: Pattern matching (simple contains)
        foreach (var recording in _recordings)
        {
            if (recording.Request.Method.Equals(request.Method.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                // Check for wildcard patterns or substring matches
                if (request.Url.Contains(recording.Request.Url, StringComparison.OrdinalIgnoreCase) ||
                    recording.Request.Url.Contains("*"))
                {
                    return recording.Response;
                }
            }
        }

        // Strategy 3: Sequential replay mode
        if (_replayOptions.SequentialMode && _globalIndex < _recordings.Count)
        {
            var recording = _recordings[_globalIndex++];
            _logger.LogDebug("Sequential replay returning response {Index} for {Url}", _globalIndex - 1, request.Url);
            return recording.Response;
        }

        return null;
    }

    /// <summary>
    /// Create a default response when no recording is found
    /// </summary>
    private static IHttpResponse CreateDefaultResponse()
    {
        return new HttpResponse
        {
            StatusCode = 404,
            Body = "{\"error\":\"No recorded response found\"}",
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
            ErrorMessage = "No matching recorded response found for request"
        };
    }

    /// <summary>
    /// Get information about loaded recordings
    /// </summary>
    public ReplayStats GetStats()
    {
        return new ReplayStats
        {
            TotalRecordings = _recordings.Count,
            UniqueUrls = _urlMappings.Keys.Count,
            RemainingResponses = _urlMappings.Values.Sum(q => q.Count),
            GlobalReplayIndex = _globalIndex
        };
    }

    /// <summary>
    /// Reset replay state
    /// </summary>
    public void Reset()
    {
        _globalIndex = 0;
        _urlMappings.Clear();
        
        // Rebuild URL mappings
        foreach (var recording in _recordings)
        {
            var url = recording.Request.Url;
            if (!_urlMappings.ContainsKey(url))
            {
                _urlMappings[url] = new Queue<RecordedInteraction>();
            }
            _urlMappings[url].Enqueue(recording);
        }
    }
}

/// <summary>
/// Statistics about replay state
/// </summary>
public class ReplayStats
{
    public int TotalRecordings { get; set; }
    public int UniqueUrls { get; set; }
    public int RemainingResponses { get; set; }
    public int GlobalReplayIndex { get; set; }
}