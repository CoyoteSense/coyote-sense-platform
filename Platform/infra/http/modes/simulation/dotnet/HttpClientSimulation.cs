using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json;
using Coyote.Infra.Http;

namespace Coyote.Infra.Http.Modes.Simulation;

/// <summary>
/// Simulation scenario configuration
/// </summary>
public class SimulationScenario
{
    public string Name { get; set; } = string.Empty;
    public string Pattern { get; set; } = string.Empty;
    public int StatusCode { get; set; } = 200;
    public string Body { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = new();
    public int MinLatencyMs { get; set; } = 0;
    public int MaxLatencyMs { get; set; } = 100;
    public double FailureRate { get; set; } = 0.0;
    public List<string> FailureMessages { get; set; } = new();
}

/// <summary>
/// Simulation HTTP client implementation with configurable behavior patterns
/// </summary>
public class SimulationHttpClient : BaseHttpClient
{
    private readonly SimulationModeOptions _simulationOptions;
    private readonly ILogger<SimulationHttpClient> _logger;
    private readonly Random _random = new();
    private readonly List<SimulationScenario> _scenarios = new();
    private readonly Dictionary<string, SimulationScenario> _defaultScenarios = new();

    public SimulationHttpClient(IOptions<HttpClientOptions> options, IOptions<HttpClientModeOptions> modeOptions, ILogger<SimulationHttpClient> logger)
        : base(options.Value)
    {
        _simulationOptions = modeOptions.Value.Simulation;
        _logger = logger;

        InitializeDefaultScenarios();
        _ = LoadScenariosAsync();
    }

    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Simulation HTTP client executing {Method} request to {Url}", request.Method, request.Url);

        var scenario = FindMatchingScenario(request);
        
        // Simulate latency
        var latency = CalculateLatency(scenario);
        if (latency > 0)
        {
            await Task.Delay(latency, cancellationToken);
        }

        // Check for simulated failure
        if (ShouldSimulateFailure(scenario))
        {
            var errorMessage = GetRandomFailureMessage(scenario);
            _logger.LogDebug("Simulation HTTP client simulating failure for {Url}: {Error}", request.Url, errorMessage);
            
            return new HttpResponse
            {
                StatusCode = 0,
                Body = string.Empty,
                Headers = new Dictionary<string, string>(),
                ErrorMessage = errorMessage
            };
        }

        // Apply global simulation effects
        var globalLatency = CalculateGlobalLatency();
        if (globalLatency > 0)
        {
            await Task.Delay(globalLatency, cancellationToken);
        }

        _logger.LogDebug("Simulation HTTP client returning status {StatusCode} for {Url}", scenario.StatusCode, request.Url);

        return new HttpResponse
        {
            StatusCode = scenario.StatusCode,
            Body = ProcessResponseBody(scenario.Body, request),
            Headers = new Dictionary<string, string>(scenario.Headers),
            ErrorMessage = scenario.StatusCode >= 400 ? $"Simulated error {scenario.StatusCode}" : null
        };
    }

    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Simulation HTTP client ping to {Url}", url);
        
        // Simulate ping latency
        var latency = _random.Next(_simulationOptions.MinPingLatencyMs, _simulationOptions.MaxPingLatencyMs);
        await Task.Delay(latency, cancellationToken);
        
        // Simulate ping failures
        if (_random.NextDouble() < _simulationOptions.PingFailureRate)
        {
            _logger.LogDebug("Simulation HTTP client simulating ping failure for {Url}", url);
            return false;
        }
        
        return true;
    }

    /// <summary>
    /// Add a custom simulation scenario
    /// </summary>
    public void AddScenario(SimulationScenario scenario)
    {
        _scenarios.Add(scenario);
        _logger.LogDebug("Added simulation scenario: {Name} for pattern {Pattern}", scenario.Name, scenario.Pattern);
    }

    /// <summary>
    /// Clear all custom scenarios
    /// </summary>
    public void ClearScenarios()
    {
        _scenarios.Clear();
        _logger.LogDebug("Cleared all simulation scenarios");
    }

    /// <summary>
    /// Get current simulation statistics
    /// </summary>
    public SimulationStats GetStats()
    {
        return new SimulationStats
        {
            TotalScenarios = _scenarios.Count + _defaultScenarios.Count,
            CustomScenarios = _scenarios.Count,
            DefaultScenarios = _defaultScenarios.Count
        };
    }

    private void InitializeDefaultScenarios()
    {
        // Default API responses
        _defaultScenarios["api-success"] = new SimulationScenario
        {
            Name = "API Success",
            Pattern = "/api/",
            StatusCode = 200,
            Body = "{\"success\": true, \"data\": \"simulated\"}",
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
            MinLatencyMs = 50,
            MaxLatencyMs = 200
        };

        _defaultScenarios["health-check"] = new SimulationScenario
        {
            Name = "Health Check",
            Pattern = "/health",
            StatusCode = 200,
            Body = "{\"status\": \"healthy\", \"timestamp\": \"{{timestamp}}\"}",
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
            MinLatencyMs = 10,
            MaxLatencyMs = 50
        };

        _defaultScenarios["slow-service"] = new SimulationScenario
        {
            Name = "Slow Service",
            Pattern = "/slow/",
            StatusCode = 200,
            Body = "{\"message\": \"slow response\"}",
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
            MinLatencyMs = 2000,
            MaxLatencyMs = 5000
        };

        _defaultScenarios["error-service"] = new SimulationScenario
        {
            Name = "Error Service",
            Pattern = "/error/",
            StatusCode = 500,
            Body = "{\"error\": \"simulated server error\"}",
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
            FailureRate = 0.3,
            FailureMessages = new List<string> { "Connection timeout", "Service unavailable", "Internal server error" }
        };

        _defaultScenarios["default"] = new SimulationScenario
        {
            Name = "Default",
            Pattern = "*",
            StatusCode = 200,
            Body = "{\"message\": \"simulation mode\", \"url\": \"{{url}}\"}",
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
            MinLatencyMs = 100,
            MaxLatencyMs = 300
        };
    }

    private async Task LoadScenariosAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(_simulationOptions.ScenarioPath) || !File.Exists(_simulationOptions.ScenarioPath))
            {
                _logger.LogDebug("No custom scenario file found at {Path}", _simulationOptions.ScenarioPath);
                return;
            }

            var json = await File.ReadAllTextAsync(_simulationOptions.ScenarioPath);
            var scenarios = JsonSerializer.Deserialize<List<SimulationScenario>>(json, new JsonSerializerOptions 
            { 
                PropertyNameCaseInsensitive = true 
            });

            if (scenarios != null)
            {
                _scenarios.AddRange(scenarios);
                _logger.LogInformation("Loaded {Count} simulation scenarios from {Path}", scenarios.Count, _simulationOptions.ScenarioPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load simulation scenarios from {Path}", _simulationOptions.ScenarioPath);
        }
    }    private SimulationScenario FindMatchingScenario(IHttpRequest request)
    {
        // Check custom scenarios first
        foreach (var scenario in _scenarios)
        {
            if (MatchesPattern(request.Url, scenario.Pattern))
            {
                _logger.LogDebug("Matched custom scenario: {Name} for {Url}", scenario.Name, request.Url);
                return scenario;
            }
        }

        // Check default scenarios in specific order (most specific first)
        var orderedScenarios = _defaultScenarios.Values
            .Where(s => s.Pattern != "*")
            .OrderByDescending(s => s.Pattern.Length)
            .Concat(_defaultScenarios.Values.Where(s => s.Pattern == "*"));

        foreach (var scenario in orderedScenarios)
        {
            if (scenario.Pattern == "*" || MatchesPattern(request.Url, scenario.Pattern))
            {
                _logger.LogDebug("Matched default scenario: {Name} for {Url}", scenario.Name, request.Url);
                return scenario;
            }
        }

        // Fallback to default
        return _defaultScenarios["default"];
    }    private static bool MatchesPattern(string url, string pattern)
    {
        if (pattern == "*") return true;
        
        // Handle patterns that start with /
        if (pattern.StartsWith("/"))
        {
            var uri = new Uri(url);
            var path = uri.AbsolutePath;
            
            if (pattern.Contains("*"))
            {
                // Convert glob pattern to regex
                var regexPattern = "^" + pattern.Replace("*", ".*") + ".*$";
                return System.Text.RegularExpressions.Regex.IsMatch(path, regexPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            else
            {
                return path.Contains(pattern, StringComparison.OrdinalIgnoreCase);
            }
        }
        
        // Handle full URL patterns
        if (pattern.Contains("*"))
        {
            var regexPattern = "^" + pattern.Replace("*", ".*") + ".*$";
            return System.Text.RegularExpressions.Regex.IsMatch(url, regexPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }
        
        return url.Contains(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private int CalculateLatency(SimulationScenario scenario)
    {
        return _random.Next(scenario.MinLatencyMs, scenario.MaxLatencyMs + 1);
    }

    private int CalculateGlobalLatency()
    {
        if (_simulationOptions.GlobalLatencyMs > 0)
        {
            return _random.Next(0, _simulationOptions.GlobalLatencyMs + 1);
        }
        return 0;
    }

    private bool ShouldSimulateFailure(SimulationScenario scenario)
    {
        if (scenario.FailureRate <= 0) return false;
        return _random.NextDouble() < scenario.FailureRate;
    }

    private string GetRandomFailureMessage(SimulationScenario scenario)
    {
        if (scenario.FailureMessages.Count == 0)
        {
            return "Simulated network failure";
        }
        var index = _random.Next(scenario.FailureMessages.Count);
        return scenario.FailureMessages[index];
    }    private string ProcessResponseBody(string body, IHttpRequest request)
    {
        // Simple template processing
        return body
            .Replace("{{url}}", request.Url)
            .Replace("{{timestamp}}", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
            .Replace("{{method}}", request.Method.ToString().ToUpperInvariant());
    }
}

/// <summary>
/// Statistics about simulation state
/// </summary>
public class SimulationStats
{
    public int TotalScenarios { get; set; }
    public int CustomScenarios { get; set; }
    public int DefaultScenarios { get; set; }
}