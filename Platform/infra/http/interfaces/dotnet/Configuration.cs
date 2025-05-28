namespace Coyote.Infra.Http;

/// <summary>
/// Runtime mode enumeration for the Coyote platform
/// </summary>
public enum RuntimeMode
{
    Production,
    Recording,
    Replay,
    Simulation,
    Debug,
    Testing
}

/// <summary>
/// Configuration options for HTTP client
/// </summary>
public class HttpClientOptions
{
    /// <summary>
    /// Default timeout in milliseconds
    /// </summary>
    public int DefaultTimeoutMs { get; set; } = 30000;
    
    /// <summary>
    /// Default headers to include in all requests
    /// </summary>
    public Dictionary<string, string> DefaultHeaders { get; set; } = new();
    
    /// <summary>
    /// Whether to verify server certificates
    /// </summary>
    public bool VerifyPeer { get; set; } = true;
    
    /// <summary>
    /// Whether to follow redirects
    /// </summary>
    public bool FollowRedirects { get; set; } = true;
    
    /// <summary>
    /// Client certificate path for mTLS
    /// </summary>
    public string? ClientCertPath { get; set; }
    
    /// <summary>
    /// Client certificate key path for mTLS
    /// </summary>
    public string? ClientKeyPath { get; set; }
    
    /// <summary>
    /// CA certificate path for server verification
    /// </summary>
    public string? CACertPath { get; set; }
    
    /// <summary>
    /// Base URL for relative requests
    /// </summary>
    public string? BaseUrl { get; set; }
    
    /// <summary>
    /// User agent string
    /// </summary>
    public string UserAgent { get; set; } = "Coyote-HttpClient/1.0";
    
    /// <summary>
    /// Maximum number of retries for failed requests
    /// </summary>
    public int MaxRetries { get; set; } = 3;
    
    /// <summary>
    /// Retry delay in milliseconds
    /// </summary>
    public int RetryDelayMs { get; set; } = 1000;
}

/// <summary>
/// Mode-specific configuration options
/// </summary>
public class HttpClientModeOptions
{
    /// <summary>
    /// Current runtime mode
    /// </summary>
    public RuntimeMode Mode { get; set; } = RuntimeMode.Production;
    
    /// <summary>
    /// Mock response configuration for testing mode
    /// </summary>
    public MockResponseOptions Mock { get; set; } = new();
    
    /// <summary>
    /// Debug mode configuration
    /// </summary>
    public DebugModeOptions Debug { get; set; } = new();
      /// <summary>
    /// Recording mode configuration
    /// </summary>
    public RecordingModeOptions Recording { get; set; } = new();
    
    /// <summary>
    /// Replay mode configuration
    /// </summary>
    public ReplayModeOptions Replay { get; set; } = new();
    
    /// <summary>
    /// Simulation mode configuration
    /// </summary>
    public SimulationModeOptions Simulation { get; set; } = new();
}

/// <summary>
/// Mock response configuration for testing
/// </summary>
public class MockResponseOptions
{
    /// <summary>
    /// Default mock response status code
    /// </summary>
    public int DefaultStatusCode { get; set; } = 200;
    
    /// <summary>
    /// Default mock response body
    /// </summary>
    public string DefaultBody { get; set; } = "{}";
    
    /// <summary>
    /// Default mock response headers
    /// </summary>
    public Dictionary<string, string> DefaultHeaders { get; set; } = new()
    {
        ["Content-Type"] = "application/json"
    };
    
    /// <summary>
    /// Simulated delay in milliseconds
    /// </summary>
    public int DelayMs { get; set; } = 0;
    
    /// <summary>
    /// Predefined responses for specific URLs
    /// </summary>
    public Dictionary<string, MockResponse> PredefinedResponses { get; set; } = new();
}

/// <summary>
/// Mock response definition
/// </summary>
public class MockResponse
{
    public int StatusCode { get; set; } = 200;
    public string Body { get; set; } = "{}";
    public Dictionary<string, string> Headers { get; set; } = new();
    public int DelayMs { get; set; } = 0;
}

/// <summary>
/// Debug mode configuration
/// </summary>
public class DebugModeOptions
{
    /// <summary>
    /// Whether to log request details
    /// </summary>
    public bool LogRequests { get; set; } = true;
    
    /// <summary>
    /// Whether to log response details
    /// </summary>
    public bool LogResponses { get; set; } = true;
    
    /// <summary>
    /// Whether to log headers
    /// </summary>
    public bool LogHeaders { get; set; } = true;
    
    /// <summary>
    /// Whether to log request/response bodies
    /// </summary>
    public bool LogBodies { get; set; } = true;
}

/// <summary>
/// Recording mode configuration
/// </summary>
public class RecordingModeOptions
{
    /// <summary>
    /// Path to store recorded requests/responses
    /// </summary>
    public string? RecordingPath { get; set; }
    
    /// <summary>
    /// Whether to record request bodies
    /// </summary>
    public bool RecordBodies { get; set; } = true;
    
    /// <summary>
    /// Whether to record headers
    /// </summary>
    public bool RecordHeaders { get; set; } = true;
}

/// <summary>
/// Replay mode configuration
/// </summary>
public class ReplayModeOptions
{
    /// <summary>
    /// Path to load recorded requests/responses from
    /// </summary>
    public string? RecordingPath { get; set; }
    
    /// <summary>
    /// Whether to use sequential replay mode (replay in order) or URL-based matching
    /// </summary>
    public bool SequentialMode { get; set; } = false;
    
    /// <summary>
    /// Whether to loop recordings when they're exhausted
    /// </summary>
    public bool LoopRecordings { get; set; } = false;
    
    /// <summary>
    /// What to do when no matching recording is found
    /// </summary>
    public ReplayFallbackMode FallbackMode { get; set; } = ReplayFallbackMode.DefaultResponse;
}

/// <summary>
/// Simulation mode configuration
/// </summary>
public class SimulationModeOptions
{
    /// <summary>
    /// Path to simulation scenario configuration file
    /// </summary>
    public string? ScenarioPath { get; set; }
    
    /// <summary>
    /// Global additional latency to add to all requests (ms)
    /// </summary>
    public int GlobalLatencyMs { get; set; } = 0;
    
    /// <summary>
    /// Global failure rate (0.0 to 1.0)
    /// </summary>
    public double GlobalFailureRate { get; set; } = 0.0;
    
    /// <summary>
    /// Minimum ping latency in milliseconds
    /// </summary>
    public int MinPingLatencyMs { get; set; } = 10;
    
    /// <summary>
    /// Maximum ping latency in milliseconds
    /// </summary>
    public int MaxPingLatencyMs { get; set; } = 100;
    
    /// <summary>
    /// Ping failure rate (0.0 to 1.0)
    /// </summary>
    public double PingFailureRate { get; set; } = 0.0;
}

/// <summary>
/// Replay fallback modes when no matching recording is found
/// </summary>
public enum ReplayFallbackMode
{
    /// <summary>
    /// Return a default 404 response
    /// </summary>
    DefaultResponse,
    
    /// <summary>
    /// Throw an exception
    /// </summary>
    ThrowException,
    
    /// <summary>
    /// Use the last available recording
    /// </summary>
    UseLastRecording
}
