using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Text.Json;
using Xunit;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Simulation;

namespace Coyote.Infra.Http.Tests;

/// <summary>
/// Unit tests for Simulation HTTP client
/// </summary>
public class SimulationHttpClientTests : IDisposable
{
    private readonly SimulationHttpClient _client;
    private readonly Mock<ILogger<SimulationHttpClient>> _mockLogger;
    private readonly string _tempScenarioPath;
    private readonly HttpClientOptions _httpOptions;
    private readonly HttpClientModeOptions _modeOptions;

    public SimulationHttpClientTests()
    {
        _mockLogger = new Mock<ILogger<SimulationHttpClient>>();
        _tempScenarioPath = Path.Combine(Path.GetTempPath(), $"scenarios_{Guid.NewGuid():N}.json");

        _httpOptions = new HttpClientOptions();
        _modeOptions = new HttpClientModeOptions
        {
            Simulation = new SimulationModeOptions
            {
                ScenarioPath = _tempScenarioPath,
                GlobalLatencyMs = 0, // Disable for testing
                GlobalFailureRate = 0.0,
                MinPingLatencyMs = 1,
                MaxPingLatencyMs = 5,
                PingFailureRate = 0.0
            }
        };

        var httpOptionsWrapper = Options.Create(_httpOptions);
        var modeOptionsWrapper = Options.Create(_modeOptions);

        _client = new SimulationHttpClient(httpOptionsWrapper, modeOptionsWrapper, _mockLogger.Object);
    }

    [Fact]
    public async Task ExecuteAsync_WithDefaultScenario_ShouldReturnSimulatedResponse()
    {
        // Arrange
        var request = new HttpRequest
        {
            Url = "https://example.com/unknown",
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.Body.Should().Contain("simulation mode");
        response.Body.Should().Contain(request.Url);
        response.Headers.Should().ContainKey("Content-Type");
    }

    [Fact]
    public async Task ExecuteAsync_WithApiPattern_ShouldMatchApiScenario()
    {
        // Arrange
        var request = new HttpRequest
        {
            Url = "https://example.com/api/users",
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.Body.Should().Contain("success");
        response.Body.Should().Contain("simulated");
    }

    [Fact]
    public async Task ExecuteAsync_WithHealthPattern_ShouldMatchHealthScenario()
    {
        // Arrange
        var request = new HttpRequest
        {
            Url = "https://example.com/health",
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.Body.Should().Contain("healthy");
        response.Body.Should().Contain("timestamp");
    }

    [Fact]
    public async Task ExecuteAsync_WithSlowPattern_ShouldHaveHigherLatency()
    {
        // Arrange
        var request = new HttpRequest
        {
            Url = "https://example.com/slow/operation",
            Method = HttpMethod.Get
        };

        var startTime = DateTime.UtcNow;

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        var duration = DateTime.UtcNow - startTime;
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        duration.TotalMilliseconds.Should().BeGreaterThan(1000); // Should have significant delay
    }

    [Fact]
    public async Task ExecuteAsync_WithErrorPattern_ShouldReturnServerError()
    {
        // Arrange
        var request = new HttpRequest
        {
            Url = "https://example.com/error/test",
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(500);
        response.Body.Should().Contain("simulated server error");
    }

    [Fact]
    public async Task ExecuteAsync_WithCustomScenario_ShouldMatchCustomBehavior()
    {
        // Arrange
        var customScenario = new SimulationScenario
        {
            Name = "Custom Test",
            Pattern = "/custom/*",
            StatusCode = 201,
            Body = "{\"custom\": \"response\"}",
            Headers = new Dictionary<string, string> { ["X-Custom"] = "true" },
            MinLatencyMs = 0,
            MaxLatencyMs = 1
        };

        _client.AddScenario(customScenario);

        var request = new HttpRequest
        {
            Url = "https://example.com/custom/endpoint",
            Method = HttpMethod.Post
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(201);
        response.Body.Should().Be("{\"custom\": \"response\"}");
        response.Headers.Should().ContainKey("X-Custom");
    }

    [Fact]
    public async Task ExecuteAsync_WithFailureScenario_ShouldSimulateNetworkFailure()
    {
        // Arrange
        var failureScenario = new SimulationScenario
        {
            Name = "Always Fail",
            Pattern = "/fail/*",
            FailureRate = 1.0, // Always fail
            FailureMessages = new List<string> { "Network timeout", "Connection refused" }
        };

        _client.AddScenario(failureScenario);

        var request = new HttpRequest
        {
            Url = "https://example.com/fail/test",
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(0);
        response.Body.Should().BeEmpty();
        response.ErrorMessage.Should().NotBeNullOrEmpty();
        (response.ErrorMessage!.Contains("Network timeout") || response.ErrorMessage.Contains("Connection refused")).Should().BeTrue();
    }

    [Fact]
    public async Task PingAsync_WithDefaultSettings_ShouldReturnTrue()
    {
        // Arrange & Act
        var result = await _client.PingAsync("https://example.com");

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task PingAsync_WithHighFailureRate_ShouldEventuallyFail()
    {
        // Arrange
        _modeOptions.Simulation.PingFailureRate = 1.0; // Always fail

        // Act & Assert
        var result = await _client.PingAsync("https://example.com");
        result.Should().BeFalse();
    }

    [Fact]
    public async Task ExecuteAsync_WithTemplateVariables_ShouldReplaceTemplates()
    {
        // Arrange
        var templateScenario = new SimulationScenario
        {
            Name = "Template Test",
            Pattern = "/template/*",
            Body = "{\"url\": \"{{url}}\", \"method\": \"{{method}}\", \"timestamp\": \"{{timestamp}}\"}"
        };

        _client.AddScenario(templateScenario);

        var request = new HttpRequest
        {
            Url = "https://example.com/template/test",
            Method = HttpMethod.Post
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.Body.Should().Contain(request.Url);
        response.Body.Should().Contain("POST");
        response.Body.Should().MatchRegex(@"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"); // ISO timestamp format
    }

    [Fact]
    public void AddScenario_ShouldIncreaseScenarioCount()
    {
        // Arrange
        var initialStats = _client.GetStats();
        var newScenario = new SimulationScenario
        {
            Name = "Test Scenario",
            Pattern = "/test/*"
        };

        // Act
        _client.AddScenario(newScenario);

        // Assert
        var newStats = _client.GetStats();
        newStats.CustomScenarios.Should().Be(initialStats.CustomScenarios + 1);
        newStats.TotalScenarios.Should().Be(initialStats.TotalScenarios + 1);
    }

    [Fact]
    public void ClearScenarios_ShouldRemoveAllCustomScenarios()
    {
        // Arrange
        _client.AddScenario(new SimulationScenario { Name = "Test1", Pattern = "/test1/*" });
        _client.AddScenario(new SimulationScenario { Name = "Test2", Pattern = "/test2/*" });

        var beforeClear = _client.GetStats();
        beforeClear.CustomScenarios.Should().Be(2);

        // Act
        _client.ClearScenarios();

        // Assert
        var afterClear = _client.GetStats();
        afterClear.CustomScenarios.Should().Be(0);
        afterClear.DefaultScenarios.Should().BeGreaterThan(0); // Default scenarios should remain
    }

    [Fact]
    public void GetStats_ShouldReturnCorrectCounts()
    {
        // Act
        var stats = _client.GetStats();

        // Assert
        stats.Should().NotBeNull();
        stats.DefaultScenarios.Should().BeGreaterThan(0);
        stats.CustomScenarios.Should().Be(0);
        stats.TotalScenarios.Should().Be(stats.DefaultScenarios + stats.CustomScenarios);
    }

    [Fact]
    public async Task LoadScenariosAsync_WithValidFile_ShouldLoadScenarios()
    {
        // Arrange
        var scenarios = new List<SimulationScenario>
        {
            new() { Name = "File Scenario 1", Pattern = "/file1/*", StatusCode = 202 },
            new() { Name = "File Scenario 2", Pattern = "/file2/*", StatusCode = 204 }
        };

        var json = JsonSerializer.Serialize(scenarios, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_tempScenarioPath, json);

        var httpOptionsWrapper = Options.Create(_httpOptions);
        var modeOptionsWrapper = Options.Create(_modeOptions);

        // Act - Create new client that will load the scenarios
        using var newClient = new SimulationHttpClient(httpOptionsWrapper, modeOptionsWrapper, _mockLogger.Object);
        
        // Give it time to load scenarios asynchronously
        await Task.Delay(100);

        // Assert
        var stats = newClient.GetStats();
        stats.CustomScenarios.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task LoadScenariosAsync_WithInvalidFile_ShouldNotThrow()
    {
        // Arrange
        await File.WriteAllTextAsync(_tempScenarioPath, "{ invalid json }");

        var httpOptionsWrapper = Options.Create(_httpOptions);
        var modeOptionsWrapper = Options.Create(_modeOptions);

        // Act & Assert - Should not throw
        using var newClient = new SimulationHttpClient(httpOptionsWrapper, modeOptionsWrapper, _mockLogger.Object);
        
        // Give it time to attempt loading
        await Task.Delay(100);

        var stats = newClient.GetStats();
        stats.Should().NotBeNull(); // Client should still work with default scenarios
    }

    public void Dispose()
    {
        _client?.Dispose();
        
        try
        {
            if (File.Exists(_tempScenarioPath))
            {
                File.Delete(_tempScenarioPath);
            }
        }
        catch
        {
            // Ignore cleanup errors in tests
        }
    }
}
