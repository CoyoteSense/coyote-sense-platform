using System;
using Coyote.Infra.Http;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Authentication client mode configuration
/// </summary>
public class AuthClientModeOptions
{
    /// <summary>
    /// Current runtime mode
    /// </summary>
    public RuntimeMode Mode { get; set; } = RuntimeMode.Production;

    /// <summary>
    /// Mock mode specific options
    /// </summary>
    public MockModeOptions Mock { get; set; } = new();

    /// <summary>
    /// Debug mode specific options
    /// </summary>
    public DebugModeOptions Debug { get; set; } = new();

    /// <summary>
    /// Real/Production mode specific options
    /// </summary>
    public RealModeOptions Real { get; set; } = new();
}

/// <summary>
/// Mock mode configuration
/// </summary>
public class MockModeOptions
{
    /// <summary>
    /// Default token expiration time in seconds
    /// </summary>
    public int DefaultExpirationSeconds { get; set; } = 3600;

    /// <summary>
    /// Whether to simulate failures
    /// </summary>
    public bool SimulateFailures { get; set; } = false;

    /// <summary>
    /// Failure probability (0.0 to 1.0)
    /// </summary>
    public double FailureProbability { get; set; } = 0.1;

    /// <summary>
    /// Simulated response delay in milliseconds
    /// </summary>
    public int ResponseDelayMs { get; set; } = 0;

    /// <summary>
    /// Whether to log mock operations
    /// </summary>
    public bool LogOperations { get; set; } = true;
}

/// <summary>
/// Debug mode configuration
/// </summary>
public class DebugModeOptions
{
    /// <summary>
    /// Whether to log authentication requests
    /// </summary>
    public bool LogRequests { get; set; } = true;

    /// <summary>
    /// Whether to log authentication responses
    /// </summary>
    public bool LogResponses { get; set; } = true;

    /// <summary>
    /// Whether to log token details (be careful with sensitive data)
    /// </summary>
    public bool LogTokens { get; set; } = false;

    /// <summary>
    /// Whether to log headers
    /// </summary>
    public bool LogHeaders { get; set; } = true;

    /// <summary>
    /// Whether to log request/response bodies
    /// </summary>
    public bool LogBodies { get; set; } = false;
}

/// <summary>
/// Real/Production mode configuration
/// </summary>
public class RealModeOptions
{
    /// <summary>
    /// Connection timeout in milliseconds
    /// </summary>
    public int ConnectionTimeoutMs { get; set; } = 30000;

    /// <summary>
    /// Request timeout in milliseconds
    /// </summary>
    public int RequestTimeoutMs { get; set; } = 60000;

    /// <summary>
    /// Maximum retry attempts
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Retry delay in milliseconds
    /// </summary>
    public int RetryDelayMs { get; set; } = 1000;

    /// <summary>
    /// Whether to enable token caching
    /// </summary>
    public bool EnableTokenCaching { get; set; } = true;

    /// <summary>
    /// Token cache duration buffer in seconds (refresh before expiry)
    /// </summary>
    public int TokenBufferSeconds { get; set; } = 300;
}
