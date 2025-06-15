using Xunit;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Real;

namespace Coyote.Infra.Http.Tests;

/// <summary>
/// Integration tests for the Real HTTP client implementation
/// </summary>
public class RealHttpClientIntegrationTests : IDisposable
{
    private readonly RealHttpClient _httpClient;
    private readonly Mock<ILogger<RealHttpClient>> _mockLogger;

    public RealHttpClientIntegrationTests()
    {
        // Create mock logger
        _mockLogger = new Mock<ILogger<RealHttpClient>>();

        // Configure HTTP client options
        var options = new HttpClientOptions
        {
            DefaultTimeoutMs = 10000,
            VerifyPeer = false // For testing purposes
        };

        _httpClient = new RealHttpClient(Options.Create(options), _mockLogger.Object);
    }

    [Fact]
    public async Task GetAsync_Should_ReturnSuccessResponse_ForValidUrl()
    {
        // Arrange
        const string testUrl = "https://httpbin.org/get";

        // Act
        var response = await _httpClient.GetAsync(testUrl);

        // Assert
        response.Should().NotBeNull();
        response.IsSuccess.Should().BeTrue();
        response.StatusCode.Should().Be(200);
        response.Body.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task PostJsonAsync_Should_SendJsonData_Successfully()
    {
        // Arrange
        const string testUrl = "https://httpbin.org/post";
        var testData = new { name = "test", value = 123 };

        // Act
        var response = await _httpClient.PostJsonAsync(testUrl, testData);

        // Assert
        response.Should().NotBeNull();
        response.IsSuccess.Should().BeTrue();
        response.StatusCode.Should().Be(200);
        response.Body.Should().Contain("\"name\": \"test\"");
        response.Body.Should().Contain("\"value\": 123");
    }

    [Fact]
    public async Task GetAsync_Should_ReturnErrorResponse_ForInvalidUrl()
    {
        // Arrange
        const string invalidUrl = "https://nonexistent-domain-12345.com/test";

        // Act
        var response = await _httpClient.GetAsync(invalidUrl);

        // Assert
        response.Should().NotBeNull();
        response.IsSuccess.Should().BeFalse();
        response.ErrorMessage.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task PingAsync_Should_ReturnTrue_ForValidUrl()
    {
        // Arrange
        const string testUrl = "https://httpbin.org";

        // Act
        var result = await _httpClient.PingAsync(testUrl);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task PingAsync_Should_ReturnFalse_ForInvalidUrl()
    {
        // Arrange
        const string invalidUrl = "https://nonexistent-domain-12345.com";

        // Act
        var result = await _httpClient.PingAsync(invalidUrl);

        // Assert
        result.Should().BeFalse();
    }    [Fact]
    public void CreateRequest_Should_ReturnConfiguredRequest()
    {
        // Act
        var request = _httpClient.CreateRequest();

        // Assert
        request.Should().NotBeNull();
        request.Method.Should().Be(HttpMethod.Get);
        request.Headers.Should().NotBeNull();
        // VerifyPeer should match the client configuration (false for testing)
        request.VerifyPeer.Should().BeFalse(); // Matches our client config
        request.FollowRedirects.Should().BeTrue();
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}
