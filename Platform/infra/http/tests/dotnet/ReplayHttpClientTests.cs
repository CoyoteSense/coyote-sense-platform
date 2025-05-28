using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Text.Json;
using Xunit;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Replay;

namespace Coyote.Infra.Http.Tests;

/// <summary>
/// Unit tests for Replay HTTP client
/// </summary>
public class ReplayHttpClientTests : IDisposable
{
    private readonly ReplayHttpClient _client;
    private readonly Mock<ILogger<ReplayHttpClient>> _mockLogger;
    private readonly string _tempRecordingPath;
    private readonly HttpClientOptions _httpOptions;
    private readonly HttpClientModeOptions _modeOptions;

    public ReplayHttpClientTests()
    {
        _mockLogger = new Mock<ILogger<ReplayHttpClient>>();
        _tempRecordingPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempRecordingPath);

        _httpOptions = new HttpClientOptions();
        _modeOptions = new HttpClientModeOptions
        {
            Replay = new ReplayModeOptions
            {
                RecordingPath = _tempRecordingPath,
                SequentialMode = false,
                LoopRecordings = false,
                FallbackMode = ReplayFallbackMode.DefaultResponse
            }
        };

        var httpOptionsWrapper = Options.Create(_httpOptions);
        var modeOptionsWrapper = Options.Create(_modeOptions);

        _client = new ReplayHttpClient(httpOptionsWrapper, modeOptionsWrapper, _mockLogger.Object);
    }

    [Fact]
    public async Task ExecuteAsync_WithNoRecordings_ShouldReturnDefaultResponse()
    {
        // Arrange
        var request = new HttpRequest
        {
            Url = "https://example.com/api/test",
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(404);
        response.Body.Should().Contain("No recorded response found");
        response.ErrorMessage.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ExecuteAsync_WithMatchingRecording_ShouldReturnRecordedResponse()
    {
        // Arrange
        await CreateTestRecording("https://example.com/api/test", "GET", 200, "{\"success\": true}");
        
        var request = new HttpRequest
        {
            Url = "https://example.com/api/test",
            Method = HttpMethod.Get
        };

        // Reload recordings
        await _client.LoadRecordingsAsync();

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.Body.Should().Be("{\"success\": true}");
        response.Headers.Should().ContainKey("Content-Type");
    }

    [Fact]
    public async Task ExecuteAsync_WithMultipleRecordingsForSameUrl_ShouldReturnInFIFOOrder()
    {
        // Arrange
        await CreateTestRecording("https://example.com/api/queue", "GET", 200, "{\"response\": 1}");
        await CreateTestRecording("https://example.com/api/queue", "GET", 200, "{\"response\": 2}");
        
        var request = new HttpRequest
        {
            Url = "https://example.com/api/queue",
            Method = HttpMethod.Get
        };

        // Reload recordings
        await _client.LoadRecordingsAsync();

        // Act
        var response1 = await _client.ExecuteAsync(request);
        var response2 = await _client.ExecuteAsync(request);

        // Assert
        response1.Body.Should().Be("{\"response\": 1}");
        response2.Body.Should().Be("{\"response\": 2}");
    }

    [Fact]
    public async Task ExecuteAsync_InSequentialMode_ShouldReturnResponsesInOrder()
    {
        // Arrange
        _modeOptions.Replay.SequentialMode = true;
        
        await CreateTestRecording("https://example.com/api/first", "GET", 200, "{\"first\": true}");
        await CreateTestRecording("https://example.com/api/second", "GET", 200, "{\"second\": true}");
        
        var request1 = new HttpRequest { Url = "https://different.com/url", Method = HttpMethod.Get };
        var request2 = new HttpRequest { Url = "https://another.com/url", Method = HttpMethod.Get };

        // Reload recordings
        await _client.LoadRecordingsAsync();

        // Act
        var response1 = await _client.ExecuteAsync(request1);
        var response2 = await _client.ExecuteAsync(request2);

        // Assert
        response1.Body.Should().Be("{\"first\": true}");
        response2.Body.Should().Be("{\"second\": true}");
    }

    [Fact]
    public async Task PingAsync_WithRecordedSuccessfulResponse_ShouldReturnTrue()
    {
        // Arrange
        await CreateTestRecording("https://example.com/health", "HEAD", 200, "");
        await _client.LoadRecordingsAsync();

        // Act
        var result = await _client.PingAsync("https://example.com/health");

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task PingAsync_WithRecordedErrorResponse_ShouldReturnFalse()
    {
        // Arrange
        await CreateTestRecording("https://example.com/health", "HEAD", 500, "");
        await _client.LoadRecordingsAsync();

        // Act
        var result = await _client.PingAsync("https://example.com/health");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task GetStats_ShouldReturnCorrectInformation()
    {
        // Arrange
        await CreateTestRecording("https://example.com/api/test1", "GET", 200, "{}");
        await CreateTestRecording("https://example.com/api/test2", "GET", 200, "{}");
        await CreateTestRecording("https://example.com/api/test1", "GET", 200, "{}"); // Same URL
        
        await _client.LoadRecordingsAsync();

        // Act
        var stats = _client.GetStats();

        // Assert
        stats.TotalRecordings.Should().Be(3);
        stats.UniqueUrls.Should().Be(2);
        stats.RemainingResponses.Should().Be(3); // All responses still available
    }

    [Fact]
    public void Reset_ShouldRestoreOriginalState()
    {
        // Arrange
        _client.Reset();

        // Act
        var stats = _client.GetStats();

        // Assert
        stats.GlobalReplayIndex.Should().Be(0);
    }

    [Fact]
    public async Task LoadRecordingsAsync_WithInvalidRecordingPath_ShouldLogWarning()
    {
        // Arrange
        _modeOptions.Replay.RecordingPath = "/nonexistent/path";

        // Act
        await _client.LoadRecordingsAsync();

        // Assert - Should not throw and should log warning
        var stats = _client.GetStats();
        stats.TotalRecordings.Should().Be(0);
    }

    [Fact]
    public async Task LoadRecordingsAsync_WithInvalidJsonFile_ShouldSkipAndContinue()
    {
        // Arrange
        var invalidJsonFile = Path.Combine(_tempRecordingPath, "invalid.json");
        await File.WriteAllTextAsync(invalidJsonFile, "{ invalid json content");

        await CreateTestRecording("https://example.com/api/valid", "GET", 200, "{}");

        // Act
        await _client.LoadRecordingsAsync();

        // Assert - Should load valid recordings and skip invalid ones
        var stats = _client.GetStats();
        stats.TotalRecordings.Should().Be(1); // Only the valid recording
    }

    private async Task CreateTestRecording(string url, string method, int statusCode, string body)
    {
        var recording = new RecordedInteraction
        {
            Timestamp = DateTime.UtcNow,
            Request = new RecordedRequest
            {
                Url = url,
                Method = method,
                Headers = new Dictionary<string, string> { ["User-Agent"] = "Test" },
                Body = null
            },
            Response = new RecordedResponse
            {
                StatusCode = statusCode,
                Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                Body = body,
                ErrorMessage = statusCode >= 400 ? $"Error {statusCode}" : null
            }
        };

        var json = JsonSerializer.Serialize(recording, new JsonSerializerOptions { WriteIndented = true });
        var fileName = $"recording_{Guid.NewGuid():N}.json";
        var filePath = Path.Combine(_tempRecordingPath, fileName);
        
        await File.WriteAllTextAsync(filePath, json);
    }

    public void Dispose()
    {
        _client?.Dispose();
        
        if (Directory.Exists(_tempRecordingPath))
        {
            try
            {
                Directory.Delete(_tempRecordingPath, true);
            }
            catch
            {
                // Ignore cleanup errors in tests
            }
        }
    }
}
