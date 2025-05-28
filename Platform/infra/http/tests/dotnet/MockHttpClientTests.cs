using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Mock;
using FluentAssertions;
using Moq;
using Xunit;

namespace Coyote.Infra.Http.Tests;

/// <summary>
/// Unit tests for Mock HTTP client
/// </summary>
public class MockHttpClientTests : IDisposable
{
    private readonly Mock<ILogger<MockHttpClient>> _loggerMock;
    private readonly MockHttpClient _client;
    private readonly HttpClientOptions _httpOptions;
    private readonly HttpClientModeOptions _modeOptions;

    public MockHttpClientTests()
    {
        _loggerMock = new Mock<ILogger<MockHttpClient>>();
        
        _httpOptions = new HttpClientOptions();
        _modeOptions = new HttpClientModeOptions
        {
            Mock = new MockResponseOptions
            {
                DefaultStatusCode = 200,
                DefaultBody = "{\"test\": \"value\"}",
                DefaultHeaders = new Dictionary<string, string> { ["Content-Type"] = "application/json" }
            }
        };

        var httpOptionsMonitor = Options.Create(_httpOptions);
        var modeOptionsMonitor = Options.Create(_modeOptions);

        _client = new MockHttpClient(httpOptionsMonitor, modeOptionsMonitor, _loggerMock.Object);
    }

    [Fact]
    public async Task ExecuteAsync_WithDefaultConfiguration_ShouldReturnDefaultResponse()
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
        response.StatusCode.Should().Be(200);
        response.Body.Should().Be("{\"test\": \"value\"}");
        response.IsSuccess.Should().BeTrue();
        response.GetHeader("Content-Type").Should().Be("application/json");
    }

    [Fact]
    public async Task GetAsync_ShouldReturnSuccessfulResponse()
    {
        // Act
        var response = await _client.GetAsync("https://example.com/api/test");

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task PostJsonAsync_ShouldReturnSuccessfulResponse()
    {
        // Arrange
        var testData = new { Name = "Test", Value = 42 };

        // Act
        var response = await _client.PostJsonAsync("https://example.com/api/test", testData);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void SetPredefinedResponse_ShouldConfigureCustomResponse()
    {
        // Arrange
        var url = "https://example.com/api/custom";
        var customBody = "{\"custom\": \"response\"}";
        var customHeaders = new Dictionary<string, string> { ["X-Custom"] = "test" };

        // Act
        _client.SetPredefinedResponse(url, 201, customBody, customHeaders);

        // Assert
        _client.GetConfiguredUrls().Should().Contain(url);
    }

    [Fact]
    public async Task ExecuteAsync_WithPredefinedResponse_ShouldReturnCustomResponse()
    {
        // Arrange
        var url = "https://example.com/api/custom";
        var customBody = "{\"custom\": \"response\"}";
        var customHeaders = new Dictionary<string, string> { ["X-Custom"] = "test" };
        
        _client.SetPredefinedResponse(url, 201, customBody, customHeaders);

        var request = new HttpRequest
        {
            Url = url,
            Method = HttpMethod.Post
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(201);
        response.Body.Should().Be(customBody);
        response.GetHeader("X-Custom").Should().Be("test");
    }

    [Fact]
    public void SetPredefinedJsonResponse_ShouldConfigureJsonResponse()
    {
        // Arrange
        var url = "https://example.com/api/json";
        var testObject = new { Message = "Hello", Count = 5 };

        // Act
        _client.SetPredefinedJsonResponse(url, testObject, 200);

        // Assert
        _client.GetConfiguredUrls().Should().Contain(url);
    }

    [Fact]
    public async Task ExecuteAsync_WithJsonResponse_ShouldReturnSerializedJson()
    {
        // Arrange
        var url = "https://example.com/api/json";
        var testObject = new { Message = "Hello", Count = 5 };
        
        _client.SetPredefinedJsonResponse(url, testObject);

        var request = new HttpRequest
        {
            Url = url,
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(200);
        response.GetHeader("Content-Type").Should().Be("application/json");
          var deserializedResponse = response.GetContent<dynamic>();
        Assert.NotNull(deserializedResponse);
    }

    [Fact]
    public void SetDefaultResponse_ShouldUpdateDefaultBehavior()
    {
        // Arrange
        var newBody = "{\"updated\": \"default\"}";
        var newHeaders = new Dictionary<string, string> { ["X-Updated"] = "true" };

        // Act
        _client.SetDefaultResponse(202, newBody, newHeaders);

        // Assert - This would be verified by subsequent requests using default response
        // The actual verification would happen in ExecuteAsync tests
    }

    [Fact]
    public async Task ExecuteAsync_WithUpdatedDefault_ShouldUseNewDefaults()
    {
        // Arrange
        var newBody = "{\"updated\": \"default\"}";
        var newHeaders = new Dictionary<string, string> { ["X-Updated"] = "true" };
        
        _client.SetDefaultResponse(202, newBody, newHeaders);

        var request = new HttpRequest
        {
            Url = "https://example.com/api/newdefault",
            Method = HttpMethod.Get
        };

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.StatusCode.Should().Be(202);
        response.Body.Should().Be(newBody);
        response.GetHeader("X-Updated").Should().Be("true");
    }

    [Fact]
    public void ClearPredefinedResponses_ShouldRemoveAllCustomResponses()
    {
        // Arrange
        _client.SetPredefinedResponse("url1", 200, "body1");
        _client.SetPredefinedResponse("url2", 201, "body2");

        // Act
        _client.ClearPredefinedResponses();

        // Assert
        _client.GetConfiguredUrls().Should().BeEmpty();
    }

    [Fact]
    public async Task PingAsync_ShouldAlwaysReturnTrue()
    {
        // Act
        var result = await _client.PingAsync("https://example.com");

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ExecuteAsync_WithDelay_ShouldRespectDelayConfiguration()
    {
        // Arrange
        var url = "https://example.com/api/delay";
        _client.SetPredefinedResponse(url, 200, "{}", delayMs: 100);

        var request = new HttpRequest
        {
            Url = url,
            Method = HttpMethod.Get
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var response = await _client.ExecuteAsync(request);

        // Assert
        stopwatch.Stop();
        response.Should().NotBeNull();
        stopwatch.ElapsedMilliseconds.Should().BeGreaterOrEqualTo(90); // Allow some variance
    }

    public void Dispose()
    {
        _client?.Dispose();
    }
}
