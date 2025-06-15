using System.Collections.Generic;

namespace Coyote.Infra.Http;

/// <summary>
/// HTTP client configuration options
/// </summary>
public class HttpClientOptions
{
    /// <summary>
    /// Default timeout for HTTP requests in milliseconds
    /// </summary>
    public int DefaultTimeoutMs { get; set; } = 30000;

    /// <summary>
    /// Whether to verify SSL/TLS peer certificates
    /// </summary>
    public bool VerifyPeer { get; set; } = true;

    /// <summary>
    /// Whether to follow HTTP redirects
    /// </summary>
    public bool FollowRedirects { get; set; } = true;

    /// <summary>
    /// Default headers to add to all requests
    /// </summary>
    public Dictionary<string, string> DefaultHeaders { get; set; } = new();

    /// <summary>
    /// Client certificate path for mTLS
    /// </summary>
    public string? ClientCertPath { get; set; }

    /// <summary>
    /// Client certificate key path for mTLS
    /// </summary>
    public string? ClientKeyPath { get; set; }    /// <summary>
    /// CA certificate path for server verification
    /// </summary>
    public string? CACertPath { get; set; }

    /// <summary>
    /// User agent string for HTTP requests
    /// </summary>
    public string UserAgent { get; set; } = "CoyoteHttp/1.0";

    /// <summary>
    /// Base URL for relative requests
    /// </summary>
    public string? BaseUrl { get; set; }
}

/// <summary>
/// Runtime modes for HTTP client
/// </summary>
public enum RuntimeMode
{
    Production,
    Testing,
    Debug,
    Recording,
    Replay,
    Simulation
}

/// <summary>
/// HTTP client mode configuration
/// </summary>
public class HttpClientModeOptions
{
    /// <summary>
    /// Current runtime mode
    /// </summary>
    public RuntimeMode Mode { get; set; } = RuntimeMode.Production;

    /// <summary>
    /// Mock mode specific configuration
    /// </summary>
    public MockModeOptions Mock { get; set; } = new();

    /// <summary>
    /// Debug mode specific configuration
    /// </summary>
    public DebugModeOptions Debug { get; set; } = new();

    /// <summary>
    /// Recording mode specific configuration
    /// </summary>
    public RecordingModeOptions Recording { get; set; } = new();

    /// <summary>
    /// Replay mode specific configuration
    /// </summary>
    public ReplayModeOptions Replay { get; set; } = new();

    /// <summary>
    /// Simulation mode specific configuration
    /// </summary>
    public SimulationModeOptions Simulation { get; set; } = new();
}

/// <summary>
/// Mock mode configuration options
/// </summary>
public class MockModeOptions
{
    /// <summary>
    /// Default delay in milliseconds for mock responses
    /// </summary>
    public int DefaultDelayMs { get; set; } = 100;

    /// <summary>
    /// Path to mock response data files
    /// </summary>
    public string? MockDataPath { get; set; }    /// <summary>
    /// Whether to randomize response delays
    /// </summary>
    public bool RandomizeDelay { get; set; } = false;

    /// <summary>
    /// Predefined responses for specific URLs
    /// </summary>
    public Dictionary<string, MockResponse> PredefinedResponses { get; set; } = new();

    /// <summary>
    /// Default status code for mock responses
    /// </summary>
    public int DefaultStatusCode { get; set; } = 200;

    /// <summary>
    /// Default body for mock responses
    /// </summary>
    public string DefaultBody { get; set; } = "{}";

    /// <summary>
    /// Default headers for mock responses
    /// </summary>
    public Dictionary<string, string> DefaultHeaders { get; set; } = new();

    /// <summary>
    /// Delay in milliseconds for mock responses (alias for DefaultDelayMs)
    /// </summary>
    public int DelayMs 
    { 
        get => DefaultDelayMs; 
        set => DefaultDelayMs = value; 
    }
}

/// <summary>
/// Debug mode configuration options
/// </summary>
public class DebugModeOptions
{
    /// <summary>
    /// Whether to log all requests and responses
    /// </summary>
    public bool LogRequestsAndResponses { get; set; } = true;

    /// <summary>
    /// Whether to include request/response bodies in logs
    /// </summary>
    public bool LogBodies { get; set; } = false;    /// <summary>
    /// Maximum body length to log (to prevent huge logs)
    /// </summary>
    public int MaxLogBodyLength { get; set; } = 1000;

    /// <summary>
    /// Whether to log HTTP requests
    /// </summary>
    public bool LogRequests { get; set; } = true;

    /// <summary>
    /// Whether to log HTTP responses
    /// </summary>
    public bool LogResponses { get; set; } = true;

    /// <summary>
    /// Whether to log HTTP headers
    /// </summary>
    public bool LogHeaders { get; set; } = true;
}

/// <summary>
/// Recording mode configuration options
/// </summary>
public class RecordingModeOptions
{
    /// <summary>
    /// Path to save recorded requests/responses
    /// </summary>
    public string? RecordingPath { get; set; }

    /// <summary>
    /// Whether to overwrite existing recordings
    /// </summary>
    public bool OverwriteExisting { get; set; } = false;
}

/// <summary>
/// Replay mode configuration options
/// </summary>
public class ReplayModeOptions
{
    /// <summary>
    /// Path to load recorded requests/responses from
    /// </summary>
    public string? ReplayPath { get; set; }

    /// <summary>
    /// Whether to fail if no matching recording is found
    /// </summary>
    public bool FailOnMissing { get; set; } = true;
}

/// <summary>
/// Simulation mode configuration options
/// </summary>
public class SimulationModeOptions
{
    /// <summary>
    /// Base delay for simulated responses
    /// </summary>
    public int BaseDelayMs { get; set; } = 100;

    /// <summary>
    /// Maximum additional random delay
    /// </summary>
    public int MaxRandomDelayMs { get; set; } = 500;    /// <summary>
    /// Probability of simulated errors (0.0 to 1.0)
    /// </summary>
    public double ErrorProbability { get; set; } = 0.0;
}

/// <summary>
/// Mock response configuration
/// </summary>
public class MockResponse
{
    /// <summary>
    /// HTTP status code
    /// </summary>
    public int StatusCode { get; set; } = 200;

    /// <summary>
    /// Response body content
    /// </summary>
    public string? Body { get; set; }

    /// <summary>
    /// Response headers
    /// </summary>
    public Dictionary<string, string> Headers { get; set; } = new();

    /// <summary>
    /// Content type header
    /// </summary>
    public string ContentType { get; set; } = "application/json";

    /// <summary>
    /// Delay before sending response (in milliseconds)
    /// </summary>
    public int DelayMs { get; set; } = 0;
}
